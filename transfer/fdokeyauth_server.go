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
	"strings"
	"time"

	fdo "github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// KeyLookup is called by the Server to check whether the presented key is
// recognized. For pull endpoints, this checks whether vouchers exist for the
// given Owner Key. For push endpoints, this checks whether the key belongs
// to a trusted Supplier. Return -1 to indicate the key is not recognized
// (allows early 404). Return 0 or positive to indicate the key is known.
type KeyLookup func(callerKey protocol.PublicKey) (count int, err error)

// TokenIssuer is called after successful authentication to generate a
// session token scoped to the authenticated key.
type TokenIssuer func(callerKey protocol.PublicKey) (token string, expiresAt time.Time, err error)

// FDOKeyAuthServer implements the Server side of the FDOKeyAuth protocol.
type FDOKeyAuthServer struct {
	// ServerKey is the Server's signing key, used to sign FDOKeyAuth.Challenge.
	ServerKey crypto.Signer

	// UsePSS controls whether RSA-PSS is used for RSA keys.
	UsePSS bool

	// HashAlg is the hash algorithm for hash continuity. Defaults to SHA-256.
	HashAlg protocol.HashAlg

	// Sessions manages FDOKeyAuth session state.
	Sessions *SessionStore

	// LookupKey checks if the presented key is recognized by the Server.
	// For pull: checks if vouchers exist for the given Owner Key.
	// For push: checks if the key belongs to a trusted Supplier.
	// If nil, the Server always proceeds with the challenge (no early 404).
	LookupKey KeyLookup

	// IssueToken generates a session token after successful authentication.
	IssueToken TokenIssuer

	// RevealVoucherExistence controls whether the Server returns 404 when the
	// key is not recognized, or always proceeds to avoid information disclosure.
	// Default false (always proceed).
	RevealVoucherExistence bool
}

// HandleHello handles POST {root}/auth/hello.
// It validates the Hello message, creates a session, and returns a signed Challenge.
func (s *FDOKeyAuthServer) HandleHello(w http.ResponseWriter, r *http.Request) {
	if s.HashAlg == 0 {
		s.HashAlg = protocol.Sha256Hash
	}

	if ct := r.Header.Get("Content-Type"); ct != "" && ct != ContentTypeCBOR {
		s.writeErrorR(w, r, http.StatusUnsupportedMediaType, "expected Content-Type: "+ContentTypeCBOR)
		return
	}

	// Read and decode FDOKeyAuth.Hello
	helloBytes, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var hello FDOKeyAuthHello
	if err := cbor.Unmarshal(helloBytes, &hello); err != nil {
		s.writeError(w, http.StatusBadRequest, "malformed CBOR: "+err.Error())
		return
	}

	// Validate protocol version
	if hello.ProtocolVersion != ProtocolVersion {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported protocol version %d", hello.ProtocolVersion))
		return
	}

	// Validate CallerKey is well-formed
	if _, err := hello.CallerKey.Public(); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid caller key: "+err.Error())
		return
	}

	// Optionally check if the key is recognized
	if s.LookupKey != nil && s.RevealVoucherExistence {
		count, err := s.LookupKey(hello.CallerKey)
		if err != nil {
			slog.Error("FDOKeyAuth.Hello: key lookup failed", "error", err)
			s.writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if count < 0 {
			s.writeError(w, http.StatusNotFound, "key not recognized")
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

	// Generate Server nonce
	nonceServer, err := GenerateNonce()
	if err != nil {
		slog.Error("FDOKeyAuth.Hello: failed to generate nonce", "error", err)
		s.writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Hash the Hello message
	hashHello := HashBytes(s.HashAlg, helloBytes)

	// Build the signed challenge payload
	challengePayload := FDOKeyAuthChallengeSignedPayload{
		TypeTag:     "FDOKeyAuth.Challenge",
		NonceCaller: hello.NonceCaller,
		NonceServer: nonceServer,
		HashHello:   hashHello,
		CallerKey:   hello.CallerKey,
	}

	serverSig, err := SignPayload(s.ServerKey, s.UsePSS, challengePayload)
	if err != nil {
		slog.Error("FDOKeyAuth.Hello: failed to sign challenge", "error", err)
		s.writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Build server info
	var serverInfo *ServerInfo
	if s.LookupKey != nil {
		count, _ := s.LookupKey(hello.CallerKey)
		if count >= 0 {
			serverInfo = &ServerInfo{VoucherCount: uint(count)}
		}
	}

	// Build the Challenge response
	challenge := FDOKeyAuthChallenge{
		NonceServer:     nonceServer,
		NonceCaller:     hello.NonceCaller,
		HashHello:       hashHello,
		ServerSignature: serverSig,
		ServerInfo:      serverInfo,
	}

	// Create session (sets challenge.SessionID)
	session := &Session{
		CallerKey:     hello.CallerKey,
		DelegateChain: hello.DelegateChain,
		NonceCaller:   hello.NonceCaller,
		NonceServer:   nonceServer,
		HashHello:     hashHello,
	}
	if err := s.Sessions.Create(session); err != nil {
		slog.Error("FDOKeyAuth.Hello: failed to create session", "error", err)
		s.writeError(w, http.StatusTooManyRequests, "too many pending sessions")
		return
	}
	challenge.SessionID = session.ID

	// Encode and store the challenge bytes for hash continuity verification
	challengeBytes, err := cbor.Marshal(challenge)
	if err != nil {
		slog.Error("FDOKeyAuth.Hello: failed to encode challenge", "error", err)
		s.writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	// Store challenge bytes in session for later hash verification
	// We need to re-fetch and update since Create already stored it
	// Instead, we store it directly in the session before Create
	session.ChallengeBytes = challengeBytes

	s.writeCBOR(w, http.StatusOK, challengeBytes)
}

// HandleProve handles POST {root}/auth/prove.
// It verifies the Caller's signature and issues a session token.
func (s *FDOKeyAuthServer) HandleProve(w http.ResponseWriter, r *http.Request) {
	if s.HashAlg == 0 {
		s.HashAlg = protocol.Sha256Hash
	}

	if ct := r.Header.Get("Content-Type"); ct != "" && ct != ContentTypeCBOR {
		s.writeErrorR(w, r, http.StatusUnsupportedMediaType, "expected Content-Type: "+ContentTypeCBOR)
		return
	}

	// Read and decode FDOKeyAuth.Prove
	proveBytes, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var prove FDOKeyAuthProve
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
	if prove.NonceServer != session.NonceServer {
		s.writeError(w, http.StatusUnauthorized, "nonce_server mismatch")
		return
	}

	// Determine verification key
	verifyKey, err := s.verificationKey(session)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "failed to determine verification key: "+err.Error())
		return
	}

	// Verify COSE_Sign1 signature
	payloadBytes, err := VerifyPayload(verifyKey, prove.CallerSignature)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "signature verification failed: "+err.Error())
		return
	}

	// Decode and verify the signed payload structure
	var provePayload FDOKeyAuthProveSignedPayload
	if err := cbor.Unmarshal(payloadBytes, &provePayload); err != nil {
		s.writeError(w, http.StatusBadRequest, "malformed prove payload: "+err.Error())
		return
	}

	// Verify payload fields
	if provePayload.TypeTag != "FDOKeyAuth.Prove" {
		s.writeError(w, http.StatusUnauthorized, "invalid message type tag")
		return
	}
	if provePayload.NonceServer != session.NonceServer {
		s.writeError(w, http.StatusUnauthorized, "nonce_server in payload mismatch")
		return
	}
	if provePayload.NonceCaller != session.NonceCaller {
		s.writeError(w, http.StatusUnauthorized, "nonce_caller in payload mismatch")
		return
	}

	// Issue session token
	if s.IssueToken == nil {
		s.writeError(w, http.StatusInternalServerError, "token issuer not configured")
		return
	}
	token, expiresAt, err := s.IssueToken(session.CallerKey)
	if err != nil {
		slog.Error("FDOKeyAuth.Prove: failed to issue token", "error", err)
		s.writeError(w, http.StatusInternalServerError, "failed to issue token")
		return
	}

	// Compute key fingerprint
	callerKeyBytes, err := cbor.Marshal(session.CallerKey)
	if err != nil {
		slog.Error("FDOKeyAuth.Prove: failed to encode caller key for fingerprint", "error", err)
		s.writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	fingerprint := sha256.Sum256(callerKeyBytes)

	// Optionally get voucher count
	var voucherCount uint
	if s.LookupKey != nil {
		count, _ := s.LookupKey(session.CallerKey)
		if count > 0 {
			voucherCount = uint(count)
		}
	}

	result := FDOKeyAuthResult{
		Status:       StatusAuthenticated,
		SessionToken: token,
		TokenExpiresAt: func() uint64 {
			if unixTime := expiresAt.Unix(); unixTime >= 0 {
				return uint64(unixTime)
			}
			return 0
		}(),
		KeyFingerprint: fingerprint[:],
		VoucherCount:   voucherCount,
	}

	resultBytes, err := cbor.Marshal(result)
	if err != nil {
		slog.Error("FDOKeyAuth.Prove: failed to encode result", "error", err)
		s.writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	slog.Info("FDOKeyAuth: authentication successful",
		"key_fingerprint", fmt.Sprintf("%x", fingerprint[:8]),
		"has_delegate", session.DelegateChain != nil,
	)

	s.writeCBOR(w, http.StatusOK, resultBytes)
}

// verificationKey returns the public key to verify the Caller's signature.
func (s *FDOKeyAuthServer) verificationKey(session *Session) (crypto.PublicKey, error) {
	if session.DelegateChain != nil && len(*session.DelegateChain) > 0 {
		// Use the leaf certificate's public key
		chain := *session.DelegateChain
		leaf := (*x509.Certificate)(chain[len(chain)-1])
		return leaf.PublicKey, nil
	}
	return session.CallerKey.Public()
}

// validateDelegateChain validates the delegate chain against the caller key
// and checks for the required voucher-claim permission.
func (s *FDOKeyAuthServer) validateDelegateChain(hello FDOKeyAuthHello) error {
	if hello.DelegateChain == nil || len(*hello.DelegateChain) == 0 {
		return fmt.Errorf("empty delegate chain")
	}

	chain := make([]*x509.Certificate, len(*hello.DelegateChain))
	for i, cert := range *hello.DelegateChain {
		chain[i] = (*x509.Certificate)(cert)
	}

	callerPub, err := hello.CallerKey.Public()
	if err != nil {
		return fmt.Errorf("failed to parse caller key: %w", err)
	}

	// Use go-fdo's delegate chain verification with the voucher-claim OID
	oid := asn1.ObjectIdentifier(fdo.OIDPermitVoucherClaim)
	if err := fdo.VerifyDelegateChain(chain, &callerPub, &oid); err != nil {
		return err
	}

	return nil
}

// writeCBOR writes a CBOR response.
func (s *FDOKeyAuthServer) writeCBOR(w http.ResponseWriter, status int, data []byte) {
	w.Header().Set("Content-Type", ContentTypeCBOR)
	w.WriteHeader(status)
	if _, err := w.Write(data); err != nil {
		slog.Error("failed to write response", "error", err)
	}
}

// writeError writes an error response. Uses JSON for error bodies for simplicity.
// Includes a request_id echoed from X-Request-ID or auto-generated.
func (s *FDOKeyAuthServer) writeError(w http.ResponseWriter, status int, msg string) {
	reqID := requestID(nil)
	slog.Debug("FDOKeyAuth error", "status", status, "message", msg, "request_id", reqID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := fmt.Fprintf(w, `{"error":%q,"request_id":%q}`, msg, reqID); err != nil {
		slog.Error("failed to write error response", "error", err)
	}
}

// writeErrorR writes an error response with request_id derived from the HTTP request.
func (s *FDOKeyAuthServer) writeErrorR(w http.ResponseWriter, r *http.Request, status int, msg string) {
	reqID := requestID(r)
	slog.Debug("FDOKeyAuth error", "status", status, "message", msg, "request_id", reqID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := fmt.Fprintf(w, `{"error":%q,"request_id":%q}`, msg, reqID); err != nil {
		slog.Error("failed to write error response", "error", err)
	}
}

// RegisterHandlers registers the FDOKeyAuth HTTP handlers on the given mux.
// The root parameter is the Service Root path (e.g., "/api/v1/pull/vouchers"
// for pull, or "/api/v1/vouchers" for push).
// Auth endpoints are registered at {root}/auth/hello and {root}/auth/prove.
func (s *FDOKeyAuthServer) RegisterHandlers(mux *http.ServeMux, root ...string) {
	prefix := "/api/v1/pull/vouchers"
	if len(root) > 0 && root[0] != "" {
		prefix = strings.TrimRight(root[0], "/")
	}
	mux.HandleFunc("POST "+prefix+"/auth/hello", s.HandleHello)
	mux.HandleFunc("POST "+prefix+"/auth/prove", s.HandleProve)
}
