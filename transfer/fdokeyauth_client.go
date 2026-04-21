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

// FDOKeyAuthClient implements the Caller side of the FDOKeyAuth protocol.
// It proves possession of a key (Owner Key for pull, Supplier Key for push)
// to a Server in order to obtain a session token for subsequent API requests.
type FDOKeyAuthClient struct {
	// CallerKey is the Caller's private key used for signing.
	// If DelegateKey is set, this is only used to identify the Caller
	// (the public key is sent in FDOKeyAuth.Hello) and DelegateKey is used for signing.
	// When using delegate-based auth, you may set CallerPublicKey instead of
	// CallerKey if you do not have the caller's private key.
	CallerKey crypto.Signer

	// CallerPublicKey is the Caller's public key, used to identify the Caller
	// in FDOKeyAuth.Hello when the Caller does not possess the corresponding
	// private key. This is the typical case for delegate-based auth: the
	// Caller holds a delegate key+cert issued by the key owner, but only
	// has the owner's public key (not private). If both CallerKey and
	// CallerPublicKey are set, CallerPublicKey takes precedence when
	// DelegateKey is also set.
	CallerPublicKey crypto.PublicKey

	// DelegateKey is an optional Delegate private key. When set, the Caller
	// signs with this key instead of CallerKey, and DelegateChain must also be set.
	DelegateKey crypto.Signer

	// DelegateChain is the X.509 certificate chain authorizing the Delegate.
	// Root first, leaf last. The root must be signed by CallerKey.
	DelegateChain []*x509.Certificate

	// UsePSS controls whether RSA-PSS is used for RSA keys (vs PKCS1v15).
	UsePSS bool

	// HashAlg is the hash algorithm to use for hash continuity.
	// Defaults to SHA-256 if not set.
	HashAlg protocol.HashAlg

	// HTTPClient is the HTTP client to use. If nil, http.DefaultClient is used.
	HTTPClient *http.Client

	// BaseURL is the Server's base URL (e.g., "https://server.example.com").
	BaseURL string

	// PathPrefix is the Service Root path on the Server.
	// All FDOKeyAuth and API endpoints are relative to this prefix.
	// Defaults to "/api/v1/pull/vouchers" if empty.
	PathPrefix string

	// ServerPublicKey is the Server's public key, used to verify the
	// ServerSignature in FDOKeyAuth.Challenge. This is typically obtained
	// from the Server's DID document. If nil, ServerSignature verification
	// is skipped with a warning logged.
	ServerPublicKey crypto.PublicKey
}

// FDOKeyAuthClientResult contains the result of a successful FDOKeyAuth handshake.
type FDOKeyAuthClientResult struct {
	SessionToken   string
	TokenExpiresAt uint64
	KeyFingerprint []byte
	VoucherCount   uint // 0 if unknown
}

// Authenticate performs the full FDOKeyAuth handshake with the Server.
// On success, returns a session token that can be used for subsequent API requests.
func (c *FDOKeyAuthClient) Authenticate() (*FDOKeyAuthClientResult, error) {
	// Validate key configuration
	if c.CallerKey == nil && c.CallerPublicKey == nil {
		return nil, fmt.Errorf("FDOKeyAuth: either CallerKey or CallerPublicKey must be set")
	}
	if c.DelegateKey != nil && c.DelegateChain == nil {
		return nil, fmt.Errorf("FDOKeyAuth: DelegateChain must be set when DelegateKey is set")
	}
	if c.CallerKey == nil && c.DelegateKey == nil {
		return nil, fmt.Errorf("FDOKeyAuth: DelegateKey must be set when using CallerPublicKey without CallerKey")
	}

	if c.HashAlg == 0 {
		c.HashAlg = protocol.Sha256Hash
	}
	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	// --- Step 1: Build and send FDOKeyAuth.Hello ---
	callerPubKey, err := c.callerPublicKey()
	if err != nil {
		return nil, fmt.Errorf("FDOKeyAuth.Hello: failed to build caller public key: %w", err)
	}

	nonceCaller, err := GenerateNonce()
	if err != nil {
		return nil, fmt.Errorf("FDOKeyAuth.Hello: %w", err)
	}

	hello := FDOKeyAuthHello{
		CallerKey:       *callerPubKey,
		NonceCaller:     nonceCaller,
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
		return nil, fmt.Errorf("FDOKeyAuth.Hello: failed to CBOR-encode: %w", err)
	}

	challengeBytes, err := c.postCBOR(client, c.pathPrefix()+"/auth/hello", helloBytes)
	if err != nil {
		return nil, fmt.Errorf("FDOKeyAuth.Hello: %w", err)
	}

	// --- Step 2: Decode and verify FDOKeyAuth.Challenge ---
	var challenge FDOKeyAuthChallenge
	if err := cbor.Unmarshal(challengeBytes, &challenge); err != nil {
		return nil, fmt.Errorf("FDOKeyAuth.Challenge: failed to decode: %w", err)
	}

	// Verify the Caller's nonce was echoed back
	if challenge.NonceCaller != nonceCaller {
		return nil, fmt.Errorf("FDOKeyAuth.Challenge: nonce_caller mismatch")
	}

	// Verify hash of Hello message
	expectedHashHello := HashBytes(c.HashAlg, helloBytes)
	if !bytes.Equal(challenge.HashHello.Value, expectedHashHello.Value) {
		return nil, fmt.Errorf("FDOKeyAuth.Challenge: hash_hello mismatch")
	}

	// Verify Server's signature
	if err := c.verifyServerSignature(challenge, nonceCaller, expectedHashHello, callerPubKey); err != nil {
		return nil, fmt.Errorf("FDOKeyAuth.Challenge: %w", err)
	}

	// --- Step 3: Build and send FDOKeyAuth.Prove ---
	hashChallenge := HashBytes(c.HashAlg, challengeBytes)

	provePayload := FDOKeyAuthProveSignedPayload{
		TypeTag:       "FDOKeyAuth.Prove",
		NonceServer:   challenge.NonceServer,
		NonceCaller:   nonceCaller,
		HashChallenge: hashChallenge,
		CallerKey:     *callerPubKey,
	}

	signingKey := c.signingKey()
	sigBytes, err := SignProvePayload(signingKey, c.UsePSS, provePayload)
	if err != nil {
		return nil, fmt.Errorf("FDOKeyAuth.Prove: failed to sign: %w", err)
	}

	prove := FDOKeyAuthProve{
		SessionID:       challenge.SessionID,
		NonceServer:     challenge.NonceServer,
		HashChallenge:   hashChallenge,
		CallerSignature: sigBytes,
	}

	resultBytes, err := c.postCBOR(client, c.pathPrefix()+"/auth/prove", mustMarshal(prove))
	if err != nil {
		return nil, fmt.Errorf("FDOKeyAuth.Prove: %w", err)
	}

	// --- Step 4: Decode FDOKeyAuth.Result ---
	var result FDOKeyAuthResult
	if err := cbor.Unmarshal(resultBytes, &result); err != nil {
		return nil, fmt.Errorf("FDOKeyAuth.Result: failed to decode: %w", err)
	}

	if result.Status != StatusAuthenticated {
		return nil, fmt.Errorf("FDOKeyAuth.Result: unexpected status %q", result.Status)
	}

	return &FDOKeyAuthClientResult{
		SessionToken:   result.SessionToken,
		TokenExpiresAt: result.TokenExpiresAt,
		KeyFingerprint: result.KeyFingerprint,
		VoucherCount:   result.VoucherCount,
	}, nil
}

// pathPrefix returns the Service Root path, defaulting to "/api/v1/pull/vouchers".
func (c *FDOKeyAuthClient) pathPrefix() string {
	if c.PathPrefix != "" {
		return strings.TrimRight(c.PathPrefix, "/")
	}
	return "/api/v1/pull/vouchers"
}

// callerPublicKey builds the protocol.PublicKey for the Caller's public key.
// When CallerPublicKey is set (delegate-based auth without caller private key),
// it is used directly. Otherwise, the public key is extracted from CallerKey.
func (c *FDOKeyAuthClient) callerPublicKey() (*protocol.PublicKey, error) {
	var pub crypto.PublicKey
	if c.CallerPublicKey != nil && c.DelegateKey != nil {
		pub = c.CallerPublicKey
	} else if c.CallerKey != nil {
		pub = c.CallerKey.Public()
	} else {
		return nil, fmt.Errorf("no caller key available")
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

// signingKey returns the key to use for signing (DelegateKey if set, otherwise CallerKey).
func (c *FDOKeyAuthClient) signingKey() crypto.Signer {
	if c.DelegateKey != nil {
		return c.DelegateKey
	}
	return c.CallerKey
}

// verifyServerSignature verifies the ServerSignature in a FDOKeyAuth.Challenge
// message. The signature is a COSE_Sign1 over a
// FDOKeyAuthChallengeSignedPayload containing the nonces, hash of Hello, and
// the Caller Key. This proves the Server possesses the private key
// corresponding to its DID-published public key.
//
// If ServerPublicKey is nil, verification is skipped with a warning.
func (c *FDOKeyAuthClient) verifyServerSignature(challenge FDOKeyAuthChallenge, nonceCaller Nonce, hashHello protocol.Hash, callerKey *protocol.PublicKey) error {
	if len(challenge.ServerSignature) == 0 {
		slog.Warn("FDOKeyAuth: ServerSignature is empty — Server did not sign the challenge")
		return nil
	}

	if c.ServerPublicKey == nil {
		slog.Warn("FDOKeyAuth: ServerPublicKey not set — skipping ServerSignature verification")
		return nil
	}

	// Step 1: Verify the COSE_Sign1 signature
	payloadBytes, err := VerifyChallengePayload(c.ServerPublicKey, challenge.ServerSignature)
	if err != nil {
		return fmt.Errorf("ServerSignature verification failed: %w", err)
	}

	// Step 2: Decode and validate the signed payload contents
	var signed FDOKeyAuthChallengeSignedPayload
	if err := cbor.Unmarshal(payloadBytes, &signed); err != nil {
		return fmt.Errorf("ServerSignature: failed to decode signed payload: %w", err)
	}

	if signed.TypeTag != "FDOKeyAuth.Challenge" {
		return fmt.Errorf("ServerSignature: unexpected type tag %q", signed.TypeTag)
	}
	if signed.NonceCaller != nonceCaller {
		return fmt.Errorf("ServerSignature: nonce_caller mismatch in signed payload")
	}
	if signed.NonceServer != challenge.NonceServer {
		return fmt.Errorf("ServerSignature: nonce_server mismatch in signed payload")
	}
	if !bytes.Equal(signed.HashHello.Value, hashHello.Value) {
		return fmt.Errorf("ServerSignature: hash_hello mismatch in signed payload")
	}

	// Verify the CallerKey in the signed payload matches what we sent
	sentKeyBytes, err := cbor.Marshal(callerKey)
	if err != nil {
		return fmt.Errorf("ServerSignature: failed to encode caller key for comparison: %w", err)
	}
	signedKeyBytes, err := cbor.Marshal(&signed.CallerKey)
	if err != nil {
		return fmt.Errorf("ServerSignature: failed to encode signed caller key for comparison: %w", err)
	}
	if !bytes.Equal(sentKeyBytes, signedKeyBytes) {
		return fmt.Errorf("ServerSignature: caller key mismatch in signed payload")
	}

	slog.Debug("FDOKeyAuth: ServerSignature verified successfully")
	return nil
}

// postCBOR sends a CBOR-encoded body to the given path and returns the response body.
func (c *FDOKeyAuthClient) postCBOR(client *http.Client, path string, body []byte) ([]byte, error) {
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
