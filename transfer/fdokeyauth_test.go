// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package transfer_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/transfer"
)

// newTestECKey generates a fresh ECDSA P-256 key for testing.
func newTestECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	return key
}

// setupTestServer creates a FDOKeyAuthServer with an httptest.Server for testing.
func setupTestServer(t *testing.T, serverKey *ecdsa.PrivateKey) (*httptest.Server, *transfer.FDOKeyAuthServer) {
	t.Helper()

	server := &transfer.FDOKeyAuthServer{
		ServerKey: serverKey,
		HashAlg:   protocol.Sha256Hash,
		Sessions:  transfer.NewSessionStore(60*time.Second, 100),
		IssueToken: func(callerKey protocol.PublicKey) (string, time.Time, error) {
			return "test-session-token-abc123", time.Now().Add(1 * time.Hour), nil
		},
	}

	mux := http.NewServeMux()
	server.RegisterHandlers(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	return ts, server
}

func TestFDOKeyAuthEndToEnd_CallerKey(t *testing.T) {
	serverKey := newTestECKey(t)
	callerKey := newTestECKey(t)

	ts, _ := setupTestServer(t, serverKey)

	client := &transfer.FDOKeyAuthClient{
		CallerKey:  callerKey,
		HashAlg:    protocol.Sha256Hash,
		HTTPClient: ts.Client(),
		BaseURL:    ts.URL,
	}

	result, err := client.Authenticate()
	if err != nil {
		t.Fatalf("FDOKeyAuth handshake failed: %v", err)
	}

	if result.SessionToken == "" {
		t.Error("expected non-empty session token")
	}
	if result.SessionToken != "test-session-token-abc123" {
		t.Errorf("unexpected session token: %s", result.SessionToken)
	}
	if result.TokenExpiresAt == 0 {
		t.Error("expected non-zero token expiration")
	}
	if len(result.KeyFingerprint) == 0 {
		t.Error("expected non-empty key fingerprint")
	}

	t.Logf("FDOKeyAuth succeeded: token=%s, expires=%d, fingerprint=%x",
		result.SessionToken, result.TokenExpiresAt, result.KeyFingerprint[:8])
}

func TestFDOKeyAuthEndToEnd_P384Key(t *testing.T) {
	serverKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	callerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	server := &transfer.FDOKeyAuthServer{
		ServerKey: serverKey,
		HashAlg:   protocol.Sha384Hash,
		Sessions:  transfer.NewSessionStore(60*time.Second, 100),
		IssueToken: func(callerKey protocol.PublicKey) (string, time.Time, error) {
			return "p384-token", time.Now().Add(1 * time.Hour), nil
		},
	}

	mux := http.NewServeMux()
	server.RegisterHandlers(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	client := &transfer.FDOKeyAuthClient{
		CallerKey:  callerKey,
		HashAlg:    protocol.Sha384Hash,
		HTTPClient: ts.Client(),
		BaseURL:    ts.URL,
	}

	result, err := client.Authenticate()
	if err != nil {
		t.Fatalf("P384 FDOKeyAuth handshake failed: %v", err)
	}
	if result.SessionToken != "p384-token" {
		t.Errorf("unexpected token: %s", result.SessionToken)
	}
}

func TestFDOKeyAuth_SessionExpired(t *testing.T) {
	serverKey := newTestECKey(t)
	callerKey := newTestECKey(t)

	// Use a very short TTL so sessions expire immediately
	server := &transfer.FDOKeyAuthServer{
		ServerKey: serverKey,
		HashAlg:   protocol.Sha256Hash,
		Sessions:  transfer.NewSessionStore(1*time.Nanosecond, 100),
		IssueToken: func(callerKey protocol.PublicKey) (string, time.Time, error) {
			return "token", time.Now().Add(1 * time.Hour), nil
		},
	}

	mux := http.NewServeMux()
	server.RegisterHandlers(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	client := &transfer.FDOKeyAuthClient{
		CallerKey:  callerKey,
		HashAlg:    protocol.Sha256Hash,
		HTTPClient: ts.Client(),
		BaseURL:    ts.URL,
	}

	// The session will expire between Hello and Prove
	time.Sleep(2 * time.Millisecond)

	_, err := client.Authenticate()
	if err == nil {
		t.Fatal("expected error due to expired session, got nil")
	}
	t.Logf("Got expected error: %v", err)
}

func TestFDOKeyAuth_KeyLookup_NotRecognized(t *testing.T) {
	serverKey := newTestECKey(t)
	callerKey := newTestECKey(t)

	server := &transfer.FDOKeyAuthServer{
		ServerKey: serverKey,
		HashAlg:   protocol.Sha256Hash,
		Sessions:  transfer.NewSessionStore(60*time.Second, 100),
		LookupKey: func(callerKey protocol.PublicKey) (int, error) {
			return -1, nil // key not recognized
		},
		RevealVoucherExistence: true,
		IssueToken: func(callerKey protocol.PublicKey) (string, time.Time, error) {
			return "token", time.Now().Add(1 * time.Hour), nil
		},
	}

	mux := http.NewServeMux()
	server.RegisterHandlers(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	client := &transfer.FDOKeyAuthClient{
		CallerKey:  callerKey,
		HashAlg:    protocol.Sha256Hash,
		HTTPClient: ts.Client(),
		BaseURL:    ts.URL,
	}

	_, err := client.Authenticate()
	if err == nil {
		t.Fatal("expected 404 error, got nil")
	}
	t.Logf("Got expected error: %v", err)
}

func TestFDOKeyAuth_KeyLookup_WithCount(t *testing.T) {
	serverKey := newTestECKey(t)
	callerKey := newTestECKey(t)

	server := &transfer.FDOKeyAuthServer{
		ServerKey: serverKey,
		HashAlg:   protocol.Sha256Hash,
		Sessions:  transfer.NewSessionStore(60*time.Second, 100),
		LookupKey: func(callerKey protocol.PublicKey) (int, error) {
			return 42, nil
		},
		IssueToken: func(callerKey protocol.PublicKey) (string, time.Time, error) {
			return "token-with-count", time.Now().Add(1 * time.Hour), nil
		},
	}

	mux := http.NewServeMux()
	server.RegisterHandlers(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	client := &transfer.FDOKeyAuthClient{
		CallerKey:  callerKey,
		HashAlg:    protocol.Sha256Hash,
		HTTPClient: ts.Client(),
		BaseURL:    ts.URL,
	}

	result, err := client.Authenticate()
	if err != nil {
		t.Fatalf("FDOKeyAuth failed: %v", err)
	}
	if result.VoucherCount != 42 {
		t.Errorf("expected voucher count 42, got %d", result.VoucherCount)
	}
}

func TestNonceGeneration(t *testing.T) {
	n1, err := transfer.GenerateNonce()
	if err != nil {
		t.Fatal(err)
	}
	n2, err := transfer.GenerateNonce()
	if err != nil {
		t.Fatal(err)
	}

	if n1 == n2 {
		t.Error("two generated nonces should not be equal")
	}

	// Verify size
	if len(n1) != transfer.NonceSize {
		t.Errorf("nonce size: got %d, want %d", len(n1), transfer.NonceSize)
	}
}

func TestHashCBOR_Deterministic(t *testing.T) {
	val := transfer.FDOKeyAuthHello{
		CallerKey:       protocol.PublicKey{},
		NonceCaller:     transfer.Nonce{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		ProtocolVersion: 1,
	}

	h1, err := transfer.HashCBOR(protocol.Sha256Hash, val)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := transfer.HashCBOR(protocol.Sha256Hash, val)
	if err != nil {
		t.Fatal(err)
	}

	if fmt.Sprintf("%x", h1.Value) != fmt.Sprintf("%x", h2.Value) {
		t.Error("CBOR hashing should be deterministic")
	}
}

func TestSignAndVerifyPayload(t *testing.T) {
	key := newTestECKey(t)

	payload := transfer.FDOKeyAuthProveSignedPayload{
		TypeTag:       "FDOKeyAuth.Prove",
		NonceServer:   transfer.Nonce{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		NonceCaller:   transfer.Nonce{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
		HashChallenge: protocol.Hash{Algorithm: protocol.Sha256Hash, Value: make([]byte, 32)},
		CallerKey:     protocol.PublicKey{},
	}

	sigBytes, err := transfer.SignProvePayload(key, false, payload)
	if err != nil {
		t.Fatalf("SignPayload failed: %v", err)
	}

	if len(sigBytes) == 0 {
		t.Fatal("expected non-empty signature bytes")
	}

	// Verify with correct key
	_, err = transfer.VerifyProvePayload(key.Public(), sigBytes)
	if err != nil {
		t.Fatalf("VerifyPayload failed with correct key: %v", err)
	}

	// Verify with wrong key should fail
	wrongKey := newTestECKey(t)
	_, err = transfer.VerifyProvePayload(wrongKey.Public(), sigBytes)
	if err == nil {
		t.Fatal("VerifyPayload should fail with wrong key")
	}
}

func TestSessionStore_SingleUse(t *testing.T) {
	store := transfer.NewSessionStore(60*time.Second, 10)

	session := &transfer.Session{
		CallerKey:   protocol.PublicKey{},
		NonceCaller: transfer.Nonce{1},
		NonceServer: transfer.Nonce{2},
	}

	if err := store.Create(session); err != nil {
		t.Fatal(err)
	}

	id := session.ID
	if len(id) == 0 {
		t.Fatal("expected non-empty session ID")
	}

	// First Get should succeed
	got := store.Get(id)
	if got == nil {
		t.Fatal("expected to find session on first Get")
	}

	// Second Get should return nil (single-use)
	got = store.Get(id)
	if got != nil {
		t.Fatal("expected nil on second Get (single-use)")
	}
}

func TestServerInfo_RejectNegativeVoucherCount(t *testing.T) {
	// Create a CBOR map with negative voucher_count
	m := map[string]any{
		"server_id":     "server.example.com",
		"voucher_count": int64(-1), // Invalid negative value
		"algorithms":    []any{int64(-7), int64(-35)},
	}
	data, err := cbor.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}

	var h transfer.ServerInfo
	err = h.UnmarshalCBOR(data)
	if err == nil {
		t.Error("expected error for negative voucher_count")
	}
	if !strings.Contains(err.Error(), "voucher_count cannot be negative") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestServerInfo_CBORMapRoundTrip(t *testing.T) {
	// Full ServerInfo
	h := transfer.ServerInfo{
		ServerID:     "server.example.com",
		VoucherCount: 42,
		Algorithms:   []int{-7, -35},
	}
	data, err := h.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	// CBOR maps start with major type 5 (0xa0-0xbf). Arrays start with 0x80-0x9f.
	// Verify it's a map, not an array.
	if data[0]&0xe0 != 0xa0 {
		t.Errorf("expected CBOR map (major type 5), got first byte 0x%02x", data[0])
	}

	var h2 transfer.ServerInfo
	if err := h2.UnmarshalCBOR(data); err != nil {
		t.Fatal(err)
	}
	if h2.ServerID != h.ServerID {
		t.Errorf("ServerID = %q, want %q", h2.ServerID, h.ServerID)
	}
	if h2.VoucherCount != h.VoucherCount {
		t.Errorf("VoucherCount = %d, want %d", h2.VoucherCount, h.VoucherCount)
	}
	if len(h2.Algorithms) != len(h.Algorithms) {
		t.Fatalf("Algorithms len = %d, want %d", len(h2.Algorithms), len(h.Algorithms))
	}
	for i, a := range h.Algorithms {
		if h2.Algorithms[i] != a {
			t.Errorf("Algorithms[%d] = %d, want %d", i, h2.Algorithms[i], a)
		}
	}

	// Minimal ServerInfo (only voucher_count)
	h3 := transfer.ServerInfo{VoucherCount: 5}
	data3, err := h3.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	if data3[0]&0xe0 != 0xa0 {
		t.Errorf("expected CBOR map for minimal ServerInfo, got 0x%02x", data3[0])
	}
	var h4 transfer.ServerInfo
	if err := h4.UnmarshalCBOR(data3); err != nil {
		t.Fatal(err)
	}
	if h4.VoucherCount != 5 {
		t.Errorf("minimal VoucherCount = %d, want 5", h4.VoucherCount)
	}
	if h4.ServerID != "" {
		t.Errorf("minimal ServerID should be empty, got %q", h4.ServerID)
	}

	// Empty ServerInfo
	h5 := transfer.ServerInfo{}
	data5, _ := h5.MarshalCBOR()
	if data5[0] != 0xa0 { // empty map
		t.Errorf("expected empty CBOR map (0xa0), got 0x%02x", data5[0])
	}
}

// TestFDOKeyAuth_ServerSignatureVerification tests that the client correctly
// verifies the Server's COSE_Sign1 signature when ServerPublicKey is set.
func TestFDOKeyAuth_ServerSignatureVerification(t *testing.T) {
	serverKey := newTestECKey(t)
	callerKey := newTestECKey(t)

	ts, _ := setupTestServer(t, serverKey)

	// Case 1: Correct ServerPublicKey — should succeed
	client := &transfer.FDOKeyAuthClient{
		CallerKey:       callerKey,
		HashAlg:         protocol.Sha256Hash,
		HTTPClient:      ts.Client(),
		BaseURL:         ts.URL,
		ServerPublicKey: serverKey.Public(),
	}

	result, err := client.Authenticate()
	if err != nil {
		t.Fatalf("FDOKeyAuth with correct ServerPublicKey failed: %v", err)
	}
	if result.SessionToken == "" {
		t.Error("expected non-empty session token")
	}
	t.Logf("ServerSignature verified successfully, token=%s", result.SessionToken)
}

func TestFDOKeyAuth_ServerSignatureVerification_WrongKey(t *testing.T) {
	serverKey := newTestECKey(t)
	callerKey := newTestECKey(t)
	wrongKey := newTestECKey(t) // different from serverKey

	ts, _ := setupTestServer(t, serverKey)

	// Case 2: Wrong ServerPublicKey — should fail
	client := &transfer.FDOKeyAuthClient{
		CallerKey:       callerKey,
		HashAlg:         protocol.Sha256Hash,
		HTTPClient:      ts.Client(),
		BaseURL:         ts.URL,
		ServerPublicKey: wrongKey.Public(),
	}

	_, err := client.Authenticate()
	if err == nil {
		t.Fatal("FDOKeyAuth with wrong ServerPublicKey should have failed")
	}
	t.Logf("Got expected error: %v", err)
}

func TestFDOKeyAuth_ServerSignatureVerification_P384(t *testing.T) {
	serverKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	callerKey := newTestECKey(t)

	ts, _ := setupTestServer(t, serverKey)

	client := &transfer.FDOKeyAuthClient{
		CallerKey:       callerKey,
		HashAlg:         protocol.Sha256Hash,
		HTTPClient:      ts.Client(),
		BaseURL:         ts.URL,
		ServerPublicKey: serverKey.Public(),
	}

	result, authErr := client.Authenticate()
	if authErr != nil {
		t.Fatalf("FDOKeyAuth with P-384 ServerKey failed: %v", authErr)
	}
	if result.SessionToken == "" {
		t.Error("expected non-empty session token")
	}
	t.Logf("P-384 ServerSignature verified successfully")
}

func TestSessionStore_Capacity(t *testing.T) {
	store := transfer.NewSessionStore(60*time.Second, 2)

	for i := 0; i < 2; i++ {
		s := &transfer.Session{NonceCaller: transfer.Nonce{byte(i)}}
		if err := store.Create(s); err != nil {
			t.Fatalf("Create %d failed: %v", i, err)
		}
	}

	// Third should fail
	s := &transfer.Session{NonceCaller: transfer.Nonce{99}}
	err := store.Create(s)
	if err == nil {
		t.Fatal("expected capacity error")
	}
	t.Logf("Got expected error: %v", err)
}
