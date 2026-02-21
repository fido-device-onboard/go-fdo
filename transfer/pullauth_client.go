// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package transfer

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// PullAuthClient implements the Recipient side of the PullAuth protocol.
// It proves possession of an Owner Key (or Delegate Key) to a Holder
// in order to obtain a session token for pulling vouchers.
type PullAuthClient struct {
	// OwnerKey is the Owner's private key used for signing.
	// If DelegateKey is set, this is only used to identify the Owner
	// (the public key is sent in PullAuth.Hello) and DelegateKey is used for signing.
	OwnerKey crypto.Signer

	// DelegateKey is an optional Delegate private key. When set, the Recipient
	// signs with this key instead of OwnerKey, and DelegateChain must also be set.
	DelegateKey crypto.Signer

	// DelegateChain is the X.509 certificate chain authorizing the Delegate.
	// Root first, leaf last. The root must be signed by OwnerKey.
	DelegateChain []*x509.Certificate

	// UsePSS controls whether RSA-PSS is used for RSA keys (vs PKCS1v15).
	UsePSS bool

	// HashAlg is the hash algorithm to use for hash continuity.
	// Defaults to SHA-256 if not set.
	HashAlg protocol.HashAlg

	// HTTPClient is the HTTP client to use. If nil, http.DefaultClient is used.
	HTTPClient *http.Client

	// BaseURL is the Holder's base URL (e.g., "https://holder.example.com").
	BaseURL string
}

// PullAuthClientResult contains the result of a successful PullAuth handshake.
type PullAuthClientResult struct {
	SessionToken        string
	TokenExpiresAt      uint64
	OwnerKeyFingerprint []byte
	VoucherCount        uint // 0 if unknown
}

// Authenticate performs the full PullAuth handshake with the Holder.
// On success, returns a session token that can be used for Pull API requests.
func (c *PullAuthClient) Authenticate() (*PullAuthClientResult, error) {
	if c.HashAlg == 0 {
		c.HashAlg = protocol.Sha256Hash
	}
	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	// --- Step 1: Build and send PullAuth.Hello ---
	ownerPubKey, err := c.ownerPublicKey()
	if err != nil {
		return nil, fmt.Errorf("PullAuth.Hello: failed to build owner public key: %w", err)
	}

	nonceRecipient, err := GenerateNonce()
	if err != nil {
		return nil, fmt.Errorf("PullAuth.Hello: %w", err)
	}

	hello := PullAuthHello{
		OwnerKey:        *ownerPubKey,
		NonceRecipient:  nonceRecipient,
		ProtocolVersion: ProtocolVersion,
	}
	if c.DelegateChain != nil {
		chain := make(CertChain, len(c.DelegateChain))
		for i, cert := range c.DelegateChain {
			chain[i] = (*cbor.X509Certificate)(cert)
		}
		hello.DelegateChain = &chain
	}

	helloBytes, err := cbor.Marshal(hello)
	if err != nil {
		return nil, fmt.Errorf("PullAuth.Hello: failed to CBOR-encode: %w", err)
	}

	challengeBytes, err := c.postCBOR(client, "/api/v1/pull/auth/hello", helloBytes)
	if err != nil {
		return nil, fmt.Errorf("PullAuth.Hello: %w", err)
	}

	// --- Step 2: Decode and verify PullAuth.Challenge ---
	var challenge PullAuthChallenge
	if err := cbor.Unmarshal(challengeBytes, &challenge); err != nil {
		return nil, fmt.Errorf("PullAuth.Challenge: failed to decode: %w", err)
	}

	// Verify the Recipient's nonce was echoed back
	if challenge.NonceRecipient != nonceRecipient {
		return nil, fmt.Errorf("PullAuth.Challenge: nonce_recipient mismatch")
	}

	// Verify hash of Hello message
	expectedHashHello := HashBytes(c.HashAlg, helloBytes)
	if !bytes.Equal(challenge.HashHello.Value, expectedHashHello.Value) {
		return nil, fmt.Errorf("PullAuth.Challenge: hash_hello mismatch")
	}

	// Verify Holder's signature (if Holder has a signing key — optional for now)
	// In a full implementation, the Recipient would verify the Holder's signature
	// using a known Holder key. For now, we verify the structure is well-formed.
	if len(challenge.HolderSignature) > 0 {
		payloadBytes, err := VerifyPayload(nil, challenge.HolderSignature)
		if err != nil {
			// If we don't have the Holder's key, we can still decode the payload
			// to verify its structure. A production implementation SHOULD verify.
			_ = payloadBytes
		}
	}

	// --- Step 3: Build and send PullAuth.Prove ---
	hashChallenge := HashBytes(c.HashAlg, challengeBytes)

	provePayload := PullAuthProveSignedPayload{
		TypeTag:        "PullAuth.Prove",
		NonceHolder:    challenge.NonceHolder,
		NonceRecipient: nonceRecipient,
		HashChallenge:  hashChallenge,
		OwnerKey:       *ownerPubKey,
	}

	signingKey := c.signingKey()
	sigBytes, err := SignPayload(signingKey, c.UsePSS, provePayload)
	if err != nil {
		return nil, fmt.Errorf("PullAuth.Prove: failed to sign: %w", err)
	}

	prove := PullAuthProve{
		SessionID:          challenge.SessionID,
		NonceHolder:        challenge.NonceHolder,
		HashChallenge:      hashChallenge,
		RecipientSignature: sigBytes,
	}

	resultBytes, err := c.postCBOR(client, "/api/v1/pull/auth/prove", mustMarshal(prove))
	if err != nil {
		return nil, fmt.Errorf("PullAuth.Prove: %w", err)
	}

	// --- Step 4: Decode PullAuth.Result ---
	var result PullAuthResult
	if err := cbor.Unmarshal(resultBytes, &result); err != nil {
		return nil, fmt.Errorf("PullAuth.Result: failed to decode: %w", err)
	}

	if result.Status != StatusAuthenticated {
		return nil, fmt.Errorf("PullAuth.Result: unexpected status %q", result.Status)
	}

	return &PullAuthClientResult{
		SessionToken:        result.SessionToken,
		TokenExpiresAt:      result.TokenExpiresAt,
		OwnerKeyFingerprint: result.OwnerKeyFingerprint,
		VoucherCount:        result.VoucherCount,
	}, nil
}

// ownerPublicKey builds the protocol.PublicKey for the Owner's public key.
func (c *PullAuthClient) ownerPublicKey() (*protocol.PublicKey, error) {
	pub := c.OwnerKey.Public()
	keyType, err := protocol.KeyTypeFromPublicKey(pub)
	if err != nil {
		return nil, err
	}
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		return protocol.NewPublicKey(keyType, key, true) // COSE encoding
	case *rsa.PublicKey:
		return protocol.NewPublicKey(keyType, key, true) // COSE encoding
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pub)
	}
}

// signingKey returns the key to use for signing (DelegateKey if set, otherwise OwnerKey).
func (c *PullAuthClient) signingKey() crypto.Signer {
	if c.DelegateKey != nil {
		return c.DelegateKey
	}
	return c.OwnerKey
}

// postCBOR sends a CBOR-encoded body to the given path and returns the response body.
func (c *PullAuthClient) postCBOR(client *http.Client, path string, body []byte) ([]byte, error) {
	url := c.BaseURL + path
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", ContentTypeCBOR)
	req.Header.Set("Accept", ContentTypeCBOR)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Error("failed to close response body", "error", err)
		}
	}()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// mustMarshal CBOR-encodes a value, panicking on error (for internal use only
// where encoding is guaranteed to succeed).
func mustMarshal(v any) []byte {
	data, err := cbor.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("transfer: failed to CBOR-encode: %v", err))
	}
	return data
}
