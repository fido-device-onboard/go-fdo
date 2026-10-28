// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package sqlite_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/fdotest"
	fdo_http "github.com/fido-device-onboard/go-fdo/http"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/sqlite"
)

func TestClient(t *testing.T) {
	newTransport := func(t *testing.T, tokens protocol.TokenService, di, to0, to1, to2 protocol.Responder) fdo.Transport {
		return &fdo_http.Transport{
			BaseURL: "http://example.com",
			Client: &http.Client{Transport: &transport{
				T: t,
				Handler: &fdo_http.Handler{
					Tokens:       tokens,
					DIResponder:  di,
					TO0Responder: to0,
					TO1Responder: to1,
					TO2Responder: to2,
				},
			}},
		}
	}

	t.Run("with mock transport", func(t *testing.T) {
		state, cleanup := newDB(t)
		defer func() { _ = cleanup() }()

		fdotest.RunClientTestSuite(t, fdotest.Config{
			State: state,
		})
	})

	t.Run("with HTTP transport at FDO 2.0", func(t *testing.T) {
		state, cleanup := newDB(t)
		defer func() { _ = cleanup() }()

		fdotest.RunClientTestSuite(t, fdotest.Config{
			State:   state,
			Version: protocol.Version200,
			NewTransport: func(t *testing.T, tokens protocol.TokenService, di, to0, to1, to2 protocol.Responder) fdo.Transport {
				tr := newTransport(t, tokens, di, to0, to1, to2).(*fdo_http.Transport)
				tr.FdoVersion = protocol.Version200
				return tr
			},
		})
	})

	t.Run("with HTTP transport", func(t *testing.T) {
		state, cleanup := newDB(t)
		defer func() { _ = cleanup() }()

		fdotest.RunClientTestSuite(t, fdotest.Config{
			State:        state,
			NewTransport: newTransport,
		})

		// After the test runs, all sessions should have been deleted, so log any
		// that remain as an error
		sessions, err := state.DB().Query("SELECT id, protocol FROM sessions")
		if err != nil {
			t.Fatal("querying sessions", err)
		}
		for sessions.Next() {
			var id []byte
			var protocol int
			if err := sessions.Scan(&id, &protocol); err != nil {
				t.Error("scanning session row", err)
			}
			t.Errorf("session wasn't invalidated [id=%x]: protocol %d", id, protocol)
		}
		if err := sessions.Err(); err != nil {
			t.Fatal("querying sessions", err)
		}
	})
}

func TestServerState(t *testing.T) {
	state, cleanup := newDB(t)
	defer func() { _ = cleanup() }()

	fdotest.RunServerStateSuite(t, state)
}

func newDB(t *testing.T) (_ *sqlite.DB, cleanup func() error) {
	cleanup = func() error { return os.Remove("db.test") }
	_ = cleanup()

	state, err := sqlite.Open("db.test", "test_password")
	if err != nil {
		t.Fatal(err)
	}
	state.DebugLog = fdotest.TestingLog(t)

	// Add manufacturer keys
	rsa2048MfgKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsa3072MfgKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	ec256MfgKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ec384MfgKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []struct {
		Type protocol.KeyType
		Key  crypto.Signer
	}{
		{
			Type: protocol.Rsa2048RestrKeyType,
			Key:  rsa2048MfgKey,
		},
		{
			Type: protocol.RsaPkcsKeyType,
			Key:  rsa2048MfgKey,
		},
		{
			Type: protocol.RsaPssKeyType,
			Key:  rsa2048MfgKey,
		},
		{
			Type: protocol.RsaPkcsKeyType,
			Key:  rsa3072MfgKey,
		},
		{
			Type: protocol.RsaPssKeyType,
			Key:  rsa3072MfgKey,
		},
		{
			Type: protocol.Secp256r1KeyType,
			Key:  ec256MfgKey,
		},
		{
			Type: protocol.Secp384r1KeyType,
			Key:  ec384MfgKey,
		},
	} {
		chain, err := generateCA(key.Key)
		if err != nil {
			t.Fatal(err)
		}
		if err := state.AddManufacturerKey(key.Type, key.Key, chain); err != nil {
			t.Fatal(err)
		}
	}

	// Add owner keys
	rsa2048OwnerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsa3072OwnerKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	ec256OwnerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ec384OwnerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for _, key := range []struct {
		Type protocol.KeyType
		Key  crypto.Signer
	}{
		{
			Type: protocol.Rsa2048RestrKeyType,
			Key:  rsa2048OwnerKey,
		},
		{
			Type: protocol.RsaPkcsKeyType,
			Key:  rsa2048OwnerKey,
		},
		{
			Type: protocol.RsaPssKeyType,
			Key:  rsa2048OwnerKey,
		},
		{
			Type: protocol.RsaPkcsKeyType,
			Key:  rsa3072OwnerKey,
		},
		{
			Type: protocol.RsaPssKeyType,
			Key:  rsa3072OwnerKey,
		},
		{
			Type: protocol.Secp256r1KeyType,
			Key:  ec256OwnerKey,
		},
		{
			Type: protocol.Secp384r1KeyType,
			Key:  ec384OwnerKey,
		},
	} {
		chain, err := generateCA(key.Key)
		if err != nil {
			t.Fatal(err)
		}
		if err := state.AddOwnerKey(key.Type, key.Key, chain); err != nil {
			t.Fatal(err)
		}
	}

	return state, cleanup
}

func generateCA(key crypto.Signer) ([]*x509.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(30 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return []*x509.Certificate{cert}, nil
}

type transport struct {
	T       *testing.T
	Handler http.Handler
}

// Assume request is well-formed and ignore timeouts, retries, etc.
func (tr *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	var buf bytes.Buffer
	rr := &httptest.ResponseRecorder{Body: &buf}
	tr.Handler.ServeHTTP(rr, req)
	resp := rr.Result()
	resp.Request = req
	return resp, nil
}

// TestSessionVersionPinning checks that a session cannot change protocol
// version (a message sent under a different URL version than the message
// that started the session is rejected before reaching the responder), nor
// protocol (a TO0 token cannot be used for TO1 or TO2 messages).
func TestSessionVersionPinning(t *testing.T) {
	state, cleanup := newDB(t)
	defer func() { _ = cleanup() }()

	handler := &fdo_http.Handler{
		Tokens:       state,
		TO0Responder: &fdo.TO0Server{Session: state, RVBlobs: state},
		TO1Responder: &fdo.TO1Server{Session: state, RVBlobs: state},
		TO2Responder: &fdo.TO2Server{Session: state, Vouchers: state, OwnerKeys: state},
	}
	post := func(version, msgType string, token string, body any) *httptest.ResponseRecorder {
		t.Helper()
		var buf bytes.Buffer
		if err := cbor.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/fdo/"+version+"/msg/"+msgType, &buf)
		req.Header.Set("Content-Type", "application/cbor")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}
	msgType := func(rr *httptest.ResponseRecorder) string { return rr.Header().Get("Message-Type") }

	// Start TO0 at FDO 2.0
	hello := post("200", "20", "", fdo.GlobalCapabilityFlags)
	if got := msgType(hello); got != "21" {
		t.Fatalf("TO0.Hello: expected HelloAck (21), got %q: %s", got, hello.Body)
	}
	token := strings.TrimPrefix(hello.Header().Get("Authorization"), "Bearer ")
	if token == "" {
		t.Fatal("no session token returned")
	}

	// Continuing the same session at 1.01 must be rejected
	rr := post("101", "22", token, []int{})
	if got := msgType(rr); got != "255" {
		t.Fatalf("expected an Error message (255) for a version change, got %q", got)
	}
	if !strings.Contains(rr.Body.String(), "session started with version 200") {
		t.Errorf("expected a version pinning error, got %q", rr.Body.String())
	}

	// A session's token cannot be used for another protocol: a TO0 token
	// must not reach the TO1 or TO2 responders
	hello = post("200", "20", "", fdo.GlobalCapabilityFlags)
	token = strings.TrimPrefix(hello.Header().Get("Authorization"), "Bearer ")
	for _, tc := range []struct{ msg, want string }{
		{"32", "TO1 message in a session started for TO0"},
		{"82", "TO2 message in a session started for TO0"},
	} {
		rr := post("200", tc.msg, token, []int{})
		if got := msgType(rr); got != "255" {
			t.Errorf("msg %s with a TO0 token: expected an Error message (255), got %q", tc.msg, got)
		}
		if !strings.Contains(rr.Body.String(), tc.want) {
			t.Errorf("msg %s with a TO0 token: expected %q, got %q", tc.msg, tc.want, rr.Body.String())
		}
	}

	// TO2 message types are only valid under their own version
	for _, tc := range []struct{ version, msg string }{{"200", "60"}, {"101", "80"}} {
		rr := post(tc.version, tc.msg, "", []int{})
		if got := msgType(rr); got != "255" {
			t.Errorf("msg %s under /%s/: expected an Error message (255), got %q", tc.msg, tc.version, got)
		}
		if !strings.Contains(rr.Body.String(), "is not part of FDO version") {
			t.Errorf("msg %s under /%s/: expected a version error, got %q", tc.msg, tc.version, rr.Body.String())
		}
	}
}
