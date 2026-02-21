// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package transfer

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	fdo "github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// VoucherLookup is called by the Holder to check whether vouchers exist
// for a given Owner Key. Implementations may return the count or 0 if unknown.
// Return -1 to indicate no vouchers exist (allows early 404).
type VoucherLookup func(ownerKey protocol.PublicKey) (count int, err error)

// TokenIssuer is called after successful authentication to generate a
// session token scoped to the authenticated Owner Key.
type TokenIssuer func(ownerKey protocol.PublicKey) (token string, expiresAt time.Time, err error)

// PullAuthServer implements the Holder side of the PullAuth protocol.
type PullAuthServer struct {
	// HolderKey is the Holder's signing key, used to sign PullAuth.Challenge.
	HolderKey crypto.Signer

	// UsePSS controls whether RSA-PSS is used for RSA keys.
	UsePSS bool

	// HashAlg is the hash algorithm for hash continuity. Defaults to SHA-256.
	HashAlg protocol.HashAlg

	// Sessions manages PullAuth session state.
	Sessions *SessionStore

	// LookupVouchers checks if vouchers exist for a given Owner Key.
	// If nil, the Holder always proceeds with the challenge (no early 404).
	LookupVouchers VoucherLookup

	// IssueToken generates a session token after successful authentication.
	IssueToken TokenIssuer

	// RevealVoucherExistence controls whether the Holder returns 404 when no
	// vouchers exist for a key, or always proceeds to avoid information disclosure.
	// Default false (always proceed).
	RevealVoucherExistence bool
}

// HandleHello handles POST /api/v1/pull/auth/hello.
// It validates the Hello message, creates a session, and returns a signed Challenge.
func (s *PullAuthServer) HandleHello(w http.ResponseWriter, r *http.Request) {
	if s.HashAlg == 0 {
		s.HashAlg = protocol.Sha256Hash
	}

	// Read and decode PullAuth.Hello
	helloBytes, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var hello PullAuthHello
	if err := cbor.Unmarshal(helloBytes, &hello); err != nil {
		s.writeError(w, http.StatusBadRequest, "malformed CBOR: "+err.Error())
		return
	}

	// Validate protocol version
	if hello.ProtocolVersion != ProtocolVersion {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported protocol version %d", hello.ProtocolVersion))
		return
	}

	// Validate OwnerKey is well-formed
	if _, err := hello.OwnerKey.Public(); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid owner key: "+err.Error())
		return
	}

	// Optionally check if vouchers exist
	if s.LookupVouchers != nil && s.RevealVoucherExistence {
		count, err := s.LookupVouchers(hello.OwnerKey)
		if err != nil {
			slog.Error("PullAuth.Hello: voucher lookup failed", "error", err)
			s.writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if count < 0 {
			s.writeError(w, http.StatusNotFound, "no vouchers for this owner key")
			return
		}
	}

	// Validate delegate chain if present
	if hello.DelegateChain != nil {
		if err := s.validateDelegateChain(hello); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid delegate chain: "+err.Error())
			return
		}
	}

	// Generate Holder nonce
	nonceHolder, err := GenerateNonce()
	if err != nil {
		slog.Error("PullAuth.Hello: failed to generate nonce", "error", err)
		s.writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Hash the Hello message
	hashHello := HashBytes(s.HashAlg, helloBytes)

	// Build the signed challenge payload
	challengePayload := PullAuthChallengeSignedPayload{
		TypeTag:        "PullAuth.Challenge",
		NonceRecipient: hello.NonceRecipient,
		NonceHolder:    nonceHolder,
		HashHello:      hashHello,
		OwnerKey:       hello.OwnerKey,
	}

	holderSig, err := SignPayload(s.HolderKey, s.UsePSS, challengePayload)
	if err != nil {
		slog.Error("PullAuth.Hello: failed to sign challenge", "error", err)
		s.writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Build holder info
	var holderInfo *HolderInfo
	if s.LookupVouchers != nil {
		count, _ := s.LookupVouchers(hello.OwnerKey)
		if count >= 0 {
			holderInfo = &HolderInfo{VoucherCount: uint(count)}
		}
	}

	// Build the Challenge response
	challenge := PullAuthChallenge{
		NonceHolder:     nonceHolder,
		NonceRecipient:  hello.NonceRecipient,
		HashHello:       hashHello,
		HolderSignature: holderSig,
		HolderInfo:      holderInfo,
	}

	// Create session (sets challenge.SessionID)
	session := &Session{
		OwnerKey:       hello.OwnerKey,
		DelegateChain:  hello.DelegateChain,
		NonceRecipient: hello.NonceRecipient,
		NonceHolder:    nonceHolder,
		HashHello:      hashHello,
	}
	if err := s.Sessions.Create(session); err != nil {
		slog.Error("PullAuth.Hello: failed to create session", "error", err)
		s.writeError(w, http.StatusTooManyRequests, "too many pending sessions")
		return
	}
	challenge.SessionID = session.ID

	// Encode and store the challenge bytes for hash continuity verification
	challengeBytes, err := cbor.Marshal(challenge)
	if err != nil {
		slog.Error("PullAuth.Hello: failed to encode challenge", "error", err)
		s.writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	// Store challenge bytes in session for later hash verification
	// We need to re-fetch and update since Create already stored it
	// Instead, we store it directly in the session before Create
	session.ChallengeBytes = challengeBytes

	s.writeCBOR(w, http.StatusOK, challengeBytes)
}

// HandleProve handles POST /api/v1/pull/auth/prove.
// It verifies the Recipient's signature and issues a session token.
func (s *PullAuthServer) HandleProve(w http.ResponseWriter, r *http.Request) {
	if s.HashAlg == 0 {
		s.HashAlg = protocol.Sha256Hash
	}

	// Read and decode PullAuth.Prove
	proveBytes, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var prove PullAuthProve
	if err := cbor.Unmarshal(proveBytes, &prove); err != nil {
		s.writeError(w, http.StatusBadRequest, "malformed CBOR: "+err.Error())
		return
	}

	// Session lookup (single-use: Get removes the session)
	session := s.Sessions.Get(prove.SessionID)
	if session == nil {
		s.writeError(w, http.StatusUnauthorized, "session not found or expired")
		return
	}

	// Hash continuity: verify hash of Challenge
	expectedHashChallenge := HashBytes(s.HashAlg, session.ChallengeBytes)
	if !bytes.Equal(prove.HashChallenge.Value, expectedHashChallenge.Value) {
		s.writeError(w, http.StatusBadRequest, "hash_challenge mismatch")
		return
	}

	// Nonce verification
	if prove.NonceHolder != session.NonceHolder {
		s.writeError(w, http.StatusUnauthorized, "nonce_holder mismatch")
		return
	}

	// Determine verification key
	verifyKey, err := s.verificationKey(session)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "failed to determine verification key: "+err.Error())
		return
	}

	// Verify COSE_Sign1 signature
	payloadBytes, err := VerifyPayload(verifyKey, prove.RecipientSignature)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "signature verification failed: "+err.Error())
		return
	}

	// Decode and verify the signed payload structure
	var provePayload PullAuthProveSignedPayload
	if err := cbor.Unmarshal(payloadBytes, &provePayload); err != nil {
		s.writeError(w, http.StatusBadRequest, "malformed prove payload: "+err.Error())
		return
	}

	// Verify payload fields
	if provePayload.TypeTag != "PullAuth.Prove" {
		s.writeError(w, http.StatusUnauthorized, "invalid message type tag")
		return
	}
	if provePayload.NonceHolder != session.NonceHolder {
		s.writeError(w, http.StatusUnauthorized, "nonce_holder in payload mismatch")
		return
	}
	if provePayload.NonceRecipient != session.NonceRecipient {
		s.writeError(w, http.StatusUnauthorized, "nonce_recipient in payload mismatch")
		return
	}

	// Issue session token
	if s.IssueToken == nil {
		s.writeError(w, http.StatusInternalServerError, "token issuer not configured")
		return
	}
	token, expiresAt, err := s.IssueToken(session.OwnerKey)
	if err != nil {
		slog.Error("PullAuth.Prove: failed to issue token", "error", err)
		s.writeError(w, http.StatusInternalServerError, "failed to issue token")
		return
	}

	// Compute owner key fingerprint
	ownerKeyBytes, err := cbor.Marshal(session.OwnerKey)
	if err != nil {
		slog.Error("PullAuth.Prove: failed to encode owner key for fingerprint", "error", err)
		s.writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	fingerprint := sha256.Sum256(ownerKeyBytes)

	// Optionally get voucher count
	var voucherCount uint
	if s.LookupVouchers != nil {
		count, _ := s.LookupVouchers(session.OwnerKey)
		if count > 0 {
			voucherCount = uint(count)
		}
	}

	result := PullAuthResult{
		Status:       StatusAuthenticated,
		SessionToken: token,
		TokenExpiresAt: func() uint64 {
			if unixTime := expiresAt.Unix(); unixTime >= 0 {
				return uint64(unixTime)
			}
			return 0
		}(),
		OwnerKeyFingerprint: fingerprint[:],
		VoucherCount:        voucherCount,
	}

	resultBytes, err := cbor.Marshal(result)
	if err != nil {
		slog.Error("PullAuth.Prove: failed to encode result", "error", err)
		s.writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	slog.Info("PullAuth: authentication successful",
		"owner_key_fingerprint", fmt.Sprintf("%x", fingerprint[:8]),
		"has_delegate", session.DelegateChain != nil,
	)

	s.writeCBOR(w, http.StatusOK, resultBytes)
}

// verificationKey returns the public key to verify the Recipient's signature.
func (s *PullAuthServer) verificationKey(session *Session) (crypto.PublicKey, error) {
	if session.DelegateChain != nil && len(*session.DelegateChain) > 0 {
		// Use the leaf certificate's public key
		chain := *session.DelegateChain
		leaf := (*x509.Certificate)(chain[len(chain)-1])
		return leaf.PublicKey, nil
	}
	return session.OwnerKey.Public()
}

// validateDelegateChain validates the delegate chain against the owner key
// and checks for the required voucher-claim permission.
func (s *PullAuthServer) validateDelegateChain(hello PullAuthHello) error {
	if hello.DelegateChain == nil || len(*hello.DelegateChain) == 0 {
		return fmt.Errorf("empty delegate chain")
	}

	chain := make([]*x509.Certificate, len(*hello.DelegateChain))
	for i, cert := range *hello.DelegateChain {
		chain[i] = (*x509.Certificate)(cert)
	}

	ownerPub, err := hello.OwnerKey.Public()
	if err != nil {
		return fmt.Errorf("failed to parse owner key: %w", err)
	}

	// Use go-fdo's delegate chain verification with the voucher-claim OID
	oid := asn1.ObjectIdentifier(fdo.OIDPermitVoucherClaim)
	if err := fdo.VerifyDelegateChain(chain, &ownerPub, &oid); err != nil {
		return err
	}

	return nil
}

// writeCBOR writes a CBOR response.
func (s *PullAuthServer) writeCBOR(w http.ResponseWriter, status int, data []byte) {
	w.Header().Set("Content-Type", ContentTypeCBOR)
	w.WriteHeader(status)
	if _, err := w.Write(data); err != nil {
		slog.Error("failed to write response", "error", err)
	}
}

// writeError writes an error response. Uses JSON for error bodies for simplicity.
func (s *PullAuthServer) writeError(w http.ResponseWriter, status int, msg string) {
	slog.Debug("PullAuth error", "status", status, "message", msg)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := fmt.Fprintf(w, `{"error":%q}`, msg); err != nil {
		slog.Error("failed to write error response", "error", err)
	}
}

// RegisterHandlers registers the PullAuth HTTP handlers on the given mux.
func (s *PullAuthServer) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/pull/auth/hello", s.HandleHello)
	mux.HandleFunc("POST /api/v1/pull/auth/prove", s.HandleProve)
}
