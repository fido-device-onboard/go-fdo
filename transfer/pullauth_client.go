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
	"strings"

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
	// When using delegate-based pull, you may set OwnerPublicKey instead of
	// OwnerKey if you do not have the owner's private key.
	OwnerKey crypto.Signer

	// OwnerPublicKey is the Owner's public key, used to identify the Owner
	// in PullAuth.Hello when the Recipient does not possess the Owner's
	// private key. This is the typical case for delegate-based pull: the
	// Recipient holds a delegate key+cert issued by the Owner, but only
	// has the Owner's public key (not private). If both OwnerKey and
	// OwnerPublicKey are set, OwnerPublicKey takes precedence when
	// DelegateKey is also set.
	OwnerPublicKey crypto.PublicKey

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

	// PathPrefix is the Pull Service Root path on the Holder.
	// All PullAuth and Pull API endpoints are relative to this prefix.
	// Defaults to "/api/v1/pull/vouchers" if empty.
	PathPrefix string

	// HolderPublicKey is the Holder's public key, used to verify the
	// HolderSignature in PullAuth.Challenge. This is typically obtained
	// from the Holder's DID document (the key in the FDOVoucherHolder
	// service entry). If nil, HolderSignature verification is skipped
	// with a warning logged.
	HolderPublicKey crypto.PublicKey
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
	// Validate key configuration
	if c.OwnerKey == nil && c.OwnerPublicKey == nil {
		return nil, fmt.Errorf("PullAuth: either OwnerKey or OwnerPublicKey must be set")
	}
	if c.DelegateKey != nil && c.DelegateChain == nil {
		return nil, fmt.Errorf("PullAuth: DelegateChain must be set when DelegateKey is set")
	}
	if c.OwnerKey == nil && c.DelegateKey == nil {
		return nil, fmt.Errorf("PullAuth: DelegateKey must be set when using OwnerPublicKey without OwnerKey")
	}

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

	challengeBytes, err := c.postCBOR(client, c.pathPrefix()+"/auth/hello", helloBytes)
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

	// Verify Holder's signature (§9.8.3)
	if err := c.verifyHolderSignature(challenge, nonceRecipient, expectedHashHello, ownerPubKey); err != nil {
		return nil, fmt.Errorf("PullAuth.Challenge: %w", err)
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

	resultBytes, err := c.postCBOR(client, c.pathPrefix()+"/auth/prove", mustMarshal(prove))
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

// pathPrefix returns the Pull Service Root path, defaulting to "/api/v1/pull/vouchers".
func (c *PullAuthClient) pathPrefix() string {
	if c.PathPrefix != "" {
		return strings.TrimRight(c.PathPrefix, "/")
	}
	return "/api/v1/pull/vouchers"
}

// ownerPublicKey builds the protocol.PublicKey for the Owner's public key.
// When OwnerPublicKey is set (delegate-based pull without owner private key),
// it is used directly. Otherwise, the public key is extracted from OwnerKey.
func (c *PullAuthClient) ownerPublicKey() (*protocol.PublicKey, error) {
	var pub crypto.PublicKey
	if c.OwnerPublicKey != nil && c.DelegateKey != nil {
		pub = c.OwnerPublicKey
	} else if c.OwnerKey != nil {
		pub = c.OwnerKey.Public()
	} else {
		return nil, fmt.Errorf("no owner key available")
	}

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

// verifyHolderSignature verifies the HolderSignature in a PullAuth.Challenge
// message per §9.8.3. The signature is a COSE_Sign1 over a
// PullAuthChallengeSignedPayload containing the nonces, hash of Hello, and
// the Owner Key. This proves the Holder possesses the private key
// corresponding to its DID-published public key.
//
// If HolderPublicKey is nil, verification is skipped with a warning.
func (c *PullAuthClient) verifyHolderSignature(challenge PullAuthChallenge, nonceRecipient Nonce, hashHello protocol.Hash, ownerKey *protocol.PublicKey) error {
	if len(challenge.HolderSignature) == 0 {
		slog.Warn("PullAuth: HolderSignature is empty — Holder did not sign the challenge")
		return nil
	}

	if c.HolderPublicKey == nil {
		slog.Warn("PullAuth: HolderPublicKey not set — skipping HolderSignature verification")
		return nil
	}

	// Step 1: Verify the COSE_Sign1 signature
	payloadBytes, err := VerifyPayload(c.HolderPublicKey, challenge.HolderSignature)
	if err != nil {
		return fmt.Errorf("HolderSignature verification failed: %w", err)
	}

	// Step 2: Decode and validate the signed payload contents
	var signed PullAuthChallengeSignedPayload
	if err := cbor.Unmarshal(payloadBytes, &signed); err != nil {
		return fmt.Errorf("HolderSignature: failed to decode signed payload: %w", err)
	}

	if signed.TypeTag != "PullAuth.Challenge" {
		return fmt.Errorf("HolderSignature: unexpected type tag %q", signed.TypeTag)
	}
	if signed.NonceRecipient != nonceRecipient {
		return fmt.Errorf("HolderSignature: nonce_recipient mismatch in signed payload")
	}
	if signed.NonceHolder != challenge.NonceHolder {
		return fmt.Errorf("HolderSignature: nonce_holder mismatch in signed payload")
	}
	if !bytes.Equal(signed.HashHello.Value, hashHello.Value) {
		return fmt.Errorf("HolderSignature: hash_hello mismatch in signed payload")
	}

	// Verify the OwnerKey in the signed payload matches what we sent
	sentKeyBytes, err := cbor.Marshal(ownerKey)
	if err != nil {
		return fmt.Errorf("HolderSignature: failed to encode owner key for comparison: %w", err)
	}
	signedKeyBytes, err := cbor.Marshal(&signed.OwnerKey)
	if err != nil {
		return fmt.Errorf("HolderSignature: failed to encode signed owner key for comparison: %w", err)
	}
	if !bytes.Equal(sentKeyBytes, signedKeyBytes) {
		return fmt.Errorf("HolderSignature: owner key mismatch in signed payload")
	}

	slog.Debug("PullAuth: HolderSignature verified successfully")
	return nil
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
