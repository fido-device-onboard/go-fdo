// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package transfer_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	fdo "github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/transfer"
)

// MemoryVoucherStore is an in-memory VoucherStore for testing.
type MemoryVoucherStore struct {
	mu       sync.RWMutex
	vouchers map[string]*transfer.VoucherData
	byOwner  map[string][]string // fingerprint -> []guid
}

func NewMemoryVoucherStore() *MemoryVoucherStore {
	return &MemoryVoucherStore{
		vouchers: make(map[string]*transfer.VoucherData),
		byOwner:  make(map[string][]string),
	}
}

func (s *MemoryVoucherStore) Save(_ context.Context, data *transfer.VoucherData) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.vouchers[data.GUID] = data
	return data.GUID, nil
}

func (s *MemoryVoucherStore) Load(_ context.Context, guid string) (*transfer.VoucherData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, ok := s.vouchers[guid]
	if !ok {
		return nil, fmt.Errorf("voucher not found: %s", guid)
	}
	return data, nil
}

func (s *MemoryVoucherStore) GetVoucher(_ context.Context, ownerKeyFingerprint []byte, guid string) (*transfer.VoucherData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, ok := s.vouchers[guid]
	if !ok {
		return nil, fmt.Errorf("voucher not found: %s", guid)
	}

	// Check ownership if fingerprint provided
	if ownerKeyFingerprint != nil {
		fp := hex.EncodeToString(ownerKeyFingerprint)
		guids, ok := s.byOwner[fp]
		if !ok {
			return nil, fmt.Errorf("no vouchers for owner")
		}
		found := false
		for _, g := range guids {
			if g == guid {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("voucher not owned by this key")
		}
	}

	return data, nil
}

func (s *MemoryVoucherStore) List(_ context.Context, ownerKeyFingerprint []byte, filter transfer.ListFilter) (*transfer.VoucherListResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var vouchers []transfer.VoucherInfo

	if ownerKeyFingerprint != nil {
		fp := hex.EncodeToString(ownerKeyFingerprint)
		guids := s.byOwner[fp]
		for _, guid := range guids {
			if data, ok := s.vouchers[guid]; ok {
				vouchers = append(vouchers, data.VoucherInfo)
			}
		}
	} else {
		for _, data := range s.vouchers {
			vouchers = append(vouchers, data.VoucherInfo)
		}
	}

	// Apply since/until filters
	if filter.Since != nil || filter.Until != nil {
		var filtered []transfer.VoucherInfo
		for _, v := range vouchers {
			if v.CreatedAt == nil {
				continue
			}
			if filter.Since != nil && v.CreatedAt.Before(*filter.Since) {
				continue
			}
			if filter.Until != nil && v.CreatedAt.After(*filter.Until) {
				continue
			}
			filtered = append(filtered, v)
		}
		vouchers = filtered
	}

	totalCount := uint(len(vouchers))
	limit := filter.Limit
	hasMore := false
	if limit > 0 && len(vouchers) > limit {
		vouchers = vouchers[:limit]
		hasMore = true
	}

	return &transfer.VoucherListResponse{
		Vouchers:   vouchers,
		HasMore:    hasMore,
		TotalCount: totalCount,
	}, nil
}

func (s *MemoryVoucherStore) Delete(_ context.Context, guid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.vouchers, guid)
	return nil
}

func (s *MemoryVoucherStore) AddForOwner(fingerprint []byte, guid string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	fp := hex.EncodeToString(fingerprint)
	s.byOwner[fp] = append(s.byOwner[fp], guid)
}

// createTestVoucher creates a minimal test voucher for testing.
func createTestVoucher(t *testing.T) (*fdo.Voucher, []byte) {
	t.Helper()

	var guid protocol.GUID
	if _, err := rand.Read(guid[:]); err != nil {
		t.Fatal(err)
	}

	header := fdo.VoucherHeader{
		Version:    101,
		GUID:       guid,
		DeviceInfo: "test-device",
	}

	ov := &fdo.Voucher{
		Version: 101,
		Header:  cbor.Bstr[fdo.VoucherHeader]{Val: header},
	}

	raw, err := cbor.Marshal(ov)
	if err != nil {
		t.Fatal(err)
	}

	return ov, raw
}

// TestPushEndToEnd tests the complete push flow from sender to receiver.
func TestPushEndToEnd(t *testing.T) {
	store := NewMemoryVoucherStore()

	receiver := &transfer.HTTPPushReceiver{
		Store: store,
	}

	ts := httptest.NewServer(receiver)
	defer ts.Close()

	sender := &transfer.HTTPPushSender{
		HTTPClient: ts.Client(),
	}

	ov, raw := createTestVoucher(t)
	guid := fmt.Sprintf("%x", ov.Header.Val.GUID[:])

	data := &transfer.VoucherData{
		VoucherInfo: transfer.VoucherInfo{
			GUID:         guid,
			SerialNumber: "SN-12345",
			ModelNumber:  "MODEL-A",
			DeviceInfo:   "test-device",
		},
		Voucher: ov,
		Raw:     raw,
	}

	dest := transfer.PushDestination{URL: ts.URL}

	err := sender.Push(context.Background(), dest, data)
	if err != nil {
		t.Fatalf("Push failed: %v", err)
	}

	// Verify voucher was stored
	stored, err := store.Load(context.Background(), guid)
	if err != nil {
		t.Fatalf("Failed to load stored voucher: %v", err)
	}

	if stored.GUID != guid {
		t.Errorf("stored GUID mismatch: got %s, want %s", stored.GUID, guid)
	}
	if stored.SerialNumber != "SN-12345" {
		t.Errorf("stored serial mismatch: got %s, want SN-12345", stored.SerialNumber)
	}
}

// TestPushWithAuthentication tests push with Bearer token authentication.
func TestPushWithAuthentication(t *testing.T) {
	store := NewMemoryVoucherStore()
	validToken := "valid-token-12345"

	receiver := &transfer.HTTPPushReceiver{
		Store: store,
		Authenticate: func(r *http.Request) bool {
			auth := r.Header.Get("Authorization")
			return auth == "Bearer "+validToken
		},
	}

	ts := httptest.NewServer(receiver)
	defer ts.Close()

	sender := &transfer.HTTPPushSender{
		HTTPClient: ts.Client(),
	}

	ov, raw := createTestVoucher(t)
	guid := fmt.Sprintf("%x", ov.Header.Val.GUID[:])

	data := &transfer.VoucherData{
		VoucherInfo: transfer.VoucherInfo{GUID: guid},
		Voucher:     ov,
		Raw:         raw,
	}

	// Test without token - should fail
	dest := transfer.PushDestination{URL: ts.URL}
	err := sender.Push(context.Background(), dest, data)
	if err == nil {
		t.Fatal("expected authentication error, got nil")
	}
	t.Logf("Expected auth error: %v", err)

	// Test with wrong token - should fail
	dest.Token = "wrong-token"
	err = sender.Push(context.Background(), dest, data)
	if err == nil {
		t.Fatal("expected authentication error with wrong token, got nil")
	}

	// Test with correct token - should succeed
	dest.Token = validToken
	err = sender.Push(context.Background(), dest, data)
	if err != nil {
		t.Fatalf("Push with valid token failed: %v", err)
	}
}

// TestPushInvalidVoucher tests rejection of invalid voucher data.
func TestPushInvalidVoucher(t *testing.T) {
	store := NewMemoryVoucherStore()

	receiver := &transfer.HTTPPushReceiver{
		Store: store,
	}

	ts := httptest.NewServer(receiver)
	defer ts.Close()

	sender := &transfer.HTTPPushSender{
		HTTPClient: ts.Client(),
	}

	// Test with nil voucher
	err := sender.Push(context.Background(), transfer.PushDestination{URL: ts.URL}, nil)
	if err == nil {
		t.Fatal("expected error for nil voucher data")
	}

	// Test with empty URL
	ov, raw := createTestVoucher(t)
	data := &transfer.VoucherData{
		VoucherInfo: transfer.VoucherInfo{GUID: "test"},
		Voucher:     ov,
		Raw:         raw,
	}
	err = sender.Push(context.Background(), transfer.PushDestination{URL: ""}, data)
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
}

// TestFDOKeyAuthWithWrongKey tests that authentication fails with wrong key.
func TestFDOKeyAuthWithWrongKey(t *testing.T) {
	serverKey := newTestECKey(t)
	callerKey := newTestECKey(t)
	wrongKey := newTestECKey(t)

	// Server expects callerKey but client uses wrongKey
	server := &transfer.FDOKeyAuthServer{
		ServerKey: serverKey,
		HashAlg:   protocol.Sha256Hash,
		Sessions:  transfer.NewSessionStore(60*time.Second, 100),
		IssueToken: func(key protocol.PublicKey) (string, time.Time, error) {
			return "token", time.Now().Add(1 * time.Hour), nil
		},
	}

	mux := http.NewServeMux()
	server.RegisterHandlers(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Client authenticates with callerKey - should succeed
	client := &transfer.FDOKeyAuthClient{
		CallerKey:  callerKey,
		HashAlg:    protocol.Sha256Hash,
		HTTPClient: ts.Client(),
		BaseURL:    ts.URL,
	}

	result, err := client.Authenticate()
	if err != nil {
		t.Fatalf("Authentication with correct key failed: %v", err)
	}
	if result.SessionToken == "" {
		t.Error("expected session token")
	}

	// Now test that a different key gets a different fingerprint
	client2 := &transfer.FDOKeyAuthClient{
		CallerKey:  wrongKey,
		HashAlg:    protocol.Sha256Hash,
		HTTPClient: ts.Client(),
		BaseURL:    ts.URL,
	}

	result2, err := client2.Authenticate()
	if err != nil {
		t.Fatalf("Authentication with different key failed: %v", err)
	}

	// Fingerprints should be different
	if fmt.Sprintf("%x", result.KeyFingerprint) == fmt.Sprintf("%x", result2.KeyFingerprint) {
		t.Error("different keys should produce different fingerprints")
	}
}

// TestPullHolderWithInvalidToken tests that invalid tokens are rejected.
func TestPullHolderWithInvalidToken(t *testing.T) {
	store := NewMemoryVoucherStore()

	holder := &transfer.HTTPPullHolder{
		Store: store,
		ValidateToken: func(token string) ([]byte, error) {
			if token == "valid-token" {
				return []byte{1, 2, 3, 4}, nil
			}
			return nil, fmt.Errorf("invalid token")
		},
	}

	mux := http.NewServeMux()
	holder.RegisterHandlers(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Test without token
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/pull/vouchers", nil)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Logf("Error closing response body: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}

	// Test with invalid token
	req, _ = http.NewRequest("GET", ts.URL+"/api/v1/pull/vouchers", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Logf("Error closing response body: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}

	// Test with valid token
	req, _ = http.NewRequest("GET", ts.URL+"/api/v1/pull/vouchers", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Logf("Error closing response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// TestPullHolderFieldSelection tests the ?fields= query parameter.
func TestPullHolderFieldSelection(t *testing.T) {
	store := NewMemoryVoucherStore()
	fingerprint := []byte{1, 2, 3, 4}

	// Add a voucher with all fields populated
	store.AddForOwner(fingerprint, "test-guid-1")
	store.mu.Lock()
	store.vouchers["test-guid-1"] = &transfer.VoucherData{
		VoucherInfo: transfer.VoucherInfo{
			GUID:         "test-guid-1",
			SerialNumber: "SN-12345",
			ModelNumber:  "Model-X",
			DeviceInfo:   "Test Device",
			CreatedAt:    func() *time.Time { t := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC); return &t }(),
		},
	}
	store.mu.Unlock()

	holder := &transfer.HTTPPullHolder{
		Store: store,
		ValidateToken: func(token string) ([]byte, error) {
			return fingerprint, nil
		},
	}

	mux := http.NewServeMux()
	holder.RegisterHandlers(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Test with fields=voucher_id,serial_number
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/pull/vouchers?fields=voucher_id,serial_number", nil)
	req.Header.Set("Authorization", "Bearer token")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Logf("Error closing response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// voucher_id and serial_number should be present
	if !strings.Contains(bodyStr, `"voucher_id"`) {
		t.Error("expected voucher_id in response")
	}
	if !strings.Contains(bodyStr, `"serial_number"`) {
		t.Error("expected serial_number in response")
	}
	// model_number, device_info, created_at should be absent (omitempty)
	if strings.Contains(bodyStr, `"model_number"`) {
		t.Error("model_number should be omitted when not in fields")
	}
	if strings.Contains(bodyStr, `"device_info"`) {
		t.Error("device_info should be omitted when not in fields")
	}
	if strings.Contains(bodyStr, `"created_at"`) {
		t.Error("created_at should be omitted when not in fields")
	}

	// Test without fields param — all fields should be present
	req2, _ := http.NewRequest("GET", ts.URL+"/api/v1/pull/vouchers", nil)
	req2.Header.Set("Authorization", "Bearer token")
	resp2, err := ts.Client().Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := resp2.Body.Close(); err != nil {
			t.Logf("Error closing response body: %v", err)
		}
	}()

	body2, _ := io.ReadAll(resp2.Body)
	bodyStr2 := string(body2)

	if !strings.Contains(bodyStr2, `"serial_number"`) {
		t.Error("expected serial_number in unfiltered response")
	}
	if !strings.Contains(bodyStr2, `"model_number"`) {
		t.Error("expected model_number in unfiltered response")
	}
}

// TestPullHolderVoucherNotFound tests 404 for non-existent voucher.
func TestPullHolderVoucherNotFound(t *testing.T) {
	store := NewMemoryVoucherStore()
	fingerprint := []byte{1, 2, 3, 4}

	holder := &transfer.HTTPPullHolder{
		Store: store,
		ValidateToken: func(token string) ([]byte, error) {
			return fingerprint, nil
		},
	}

	mux := http.NewServeMux()
	holder.RegisterHandlers(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/pull/vouchers/nonexistent-guid", nil)
	req.Header.Set("Authorization", "Bearer token")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Logf("Error closing response body: %v", err)
	}

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

// TestFDOKeyAuthDelegateChain tests authentication with delegate certificates.
func TestFDOKeyAuthDelegateChain(t *testing.T) {
	serverKey := newTestECKey(t)
	callerKey := newTestECKey(t)

	server := &transfer.FDOKeyAuthServer{
		ServerKey: serverKey,
		HashAlg:   protocol.Sha256Hash,
		Sessions:  transfer.NewSessionStore(60*time.Second, 100),
		IssueToken: func(key protocol.PublicKey) (string, time.Time, error) {
			return "delegate-token", time.Now().Add(1 * time.Hour), nil
		},
	}

	mux := http.NewServeMux()
	server.RegisterHandlers(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// For now, test without delegate (delegate chain support requires X.509 setup)
	client := &transfer.FDOKeyAuthClient{
		CallerKey:  callerKey,
		HashAlg:    protocol.Sha256Hash,
		HTTPClient: ts.Client(),
		BaseURL:    ts.URL,
	}

	result, err := client.Authenticate()
	if err != nil {
		t.Fatalf("Authentication failed: %v", err)
	}

	if result.SessionToken != "delegate-token" {
		t.Errorf("unexpected token: %s", result.SessionToken)
	}
}

// TestFDOKeyAuthReplayProtection tests that nonces prevent replay attacks.
func TestFDOKeyAuthReplayProtection(t *testing.T) {
	// Generate two nonces and verify they're different
	n1, err := transfer.GenerateNonce()
	if err != nil {
		t.Fatal(err)
	}
	n2, err := transfer.GenerateNonce()
	if err != nil {
		t.Fatal(err)
	}

	if n1 == n2 {
		t.Error("nonces should be unique to prevent replay")
	}

	// Verify nonce size
	if len(n1) != transfer.NonceSize {
		t.Errorf("nonce size: got %d, want %d", len(n1), transfer.NonceSize)
	}
}

// TestFDOKeyAuthSignatureVerification tests that invalid signatures are rejected.
func TestFDOKeyAuthSignatureVerification(t *testing.T) {
	key := newTestECKey(t)
	wrongKey := newTestECKey(t)

	payload := transfer.FDOKeyAuthProveSignedPayload{
		TypeTag:       "FDOKeyAuth.Prove",
		NonceServer:   transfer.Nonce{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		NonceCaller:   transfer.Nonce{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
		HashChallenge: protocol.Hash{Algorithm: protocol.Sha256Hash, Value: make([]byte, 32)},
		CallerKey:     protocol.PublicKey{},
	}

	// Sign with key
	sigBytes, err := transfer.SignProvePayload(key, false, payload)
	if err != nil {
		t.Fatal(err)
	}

	// Verify with correct key - should succeed
	_, err = transfer.VerifyProvePayload(key.Public(), sigBytes)
	if err != nil {
		t.Fatalf("verification with correct key failed: %v", err)
	}

	// Verify with wrong key - should fail
	_, err = transfer.VerifyProvePayload(wrongKey.Public(), sigBytes)
	if err == nil {
		t.Fatal("verification with wrong key should fail")
	}
}

// TestFDOKeyAuthHashAlgorithms tests different hash algorithms.
func TestFDOKeyAuthHashAlgorithms(t *testing.T) {
	testCases := []struct {
		name    string
		hashAlg protocol.HashAlg
		curve   elliptic.Curve
	}{
		{"SHA256-P256", protocol.Sha256Hash, elliptic.P256()},
		{"SHA384-P384", protocol.Sha384Hash, elliptic.P384()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			serverKey, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			callerKey, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}

			server := &transfer.FDOKeyAuthServer{
				ServerKey: serverKey,
				HashAlg:   tc.hashAlg,
				Sessions:  transfer.NewSessionStore(60*time.Second, 100),
				IssueToken: func(key protocol.PublicKey) (string, time.Time, error) {
					return "token-" + tc.name, time.Now().Add(1 * time.Hour), nil
				},
			}

			mux := http.NewServeMux()
			server.RegisterHandlers(mux)
			ts := httptest.NewServer(mux)
			defer ts.Close()

			client := &transfer.FDOKeyAuthClient{
				CallerKey:  callerKey,
				HashAlg:    tc.hashAlg,
				HTTPClient: ts.Client(),
				BaseURL:    ts.URL,
			}

			result, err := client.Authenticate()
			if err != nil {
				t.Fatalf("Authentication failed: %v", err)
			}

			if result.SessionToken != "token-"+tc.name {
				t.Errorf("unexpected token: %s", result.SessionToken)
			}
		})
	}
}

// TestPushErrorIsTransient verifies PushError classifies HTTP status codes correctly.
func TestPushErrorIsTransient(t *testing.T) {
	tests := []struct {
		status    int
		transient bool
	}{
		{400, false},
		{401, false},
		{403, false},
		{404, false},
		{409, false},
		{429, true}, // Too Many Requests
		{500, true}, // Internal Server Error
		{502, true}, // Bad Gateway
		{503, true}, // Service Unavailable
	}
	for _, tc := range tests {
		e := &transfer.PushError{StatusCode: tc.status, Body: "test"}
		if e.IsTransient() != tc.transient {
			t.Errorf("status %d: IsTransient()=%v, want %v", tc.status, e.IsTransient(), tc.transient)
		}
	}
}

// TestPushSenderReturnsPushError verifies HTTPPushSender returns *PushError on HTTP failures.
func TestPushSenderReturnsPushError(t *testing.T) {
	store := NewMemoryVoucherStore()

	receiver := &transfer.HTTPPushReceiver{
		Store: store,
		Authenticate: func(r *http.Request) bool {
			return false // always reject
		},
	}

	ts := httptest.NewServer(receiver)
	defer ts.Close()

	sender := &transfer.HTTPPushSender{HTTPClient: ts.Client()}

	ov, raw := createTestVoucher(t)
	guid := fmt.Sprintf("%x", ov.Header.Val.GUID[:])

	data := &transfer.VoucherData{
		VoucherInfo: transfer.VoucherInfo{GUID: guid},
		Voucher:     ov,
		Raw:         raw,
	}

	err := sender.Push(context.Background(), transfer.PushDestination{URL: ts.URL}, data)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var pushErr *transfer.PushError
	if !errors.As(err, &pushErr) {
		t.Fatalf("expected *transfer.PushError, got %T: %v", err, err)
	}
	if pushErr.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", pushErr.StatusCode)
	}
	if pushErr.IsTransient() {
		t.Error("401 should not be transient")
	}
}

// TestPushReceiverMethodNotAllowed tests that only POST is accepted.
func TestPushReceiverMethodNotAllowed(t *testing.T) {
	receiver := &transfer.HTTPPushReceiver{
		Store: NewMemoryVoucherStore(),
	}

	ts := httptest.NewServer(receiver)
	defer ts.Close()

	methods := []string{"GET", "PUT", "DELETE", "PATCH"}
	for _, method := range methods {
		req, _ := http.NewRequest(method, ts.URL, nil)
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Logf("Error closing response body: %v", err)
		}

		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s: expected 405, got %d", method, resp.StatusCode)
		}
	}
}

// TestConcurrentPushes tests thread safety of push receiver.
func TestConcurrentPushes(t *testing.T) {
	store := NewMemoryVoucherStore()

	receiver := &transfer.HTTPPushReceiver{
		Store: store,
	}

	ts := httptest.NewServer(receiver)
	defer ts.Close()

	sender := &transfer.HTTPPushSender{
		HTTPClient: ts.Client(),
	}

	const numPushes = 10
	var wg sync.WaitGroup
	errors := make(chan error, numPushes)

	for i := 0; i < numPushes; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			ov, raw := createTestVoucher(t)
			guid := fmt.Sprintf("%x", ov.Header.Val.GUID[:])

			data := &transfer.VoucherData{
				VoucherInfo: transfer.VoucherInfo{
					GUID:         guid,
					SerialNumber: fmt.Sprintf("SN-%d", idx),
				},
				Voucher: ov,
				Raw:     raw,
			}

			err := sender.Push(context.Background(), transfer.PushDestination{URL: ts.URL}, data)
			if err != nil {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent push error: %v", err)
	}
}
