// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package http_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/fido-device-onboard/go-fdo/cbor"
	fdo_http "github.com/fido-device-onboard/go-fdo/http"
	"github.com/fido-device-onboard/go-fdo/http/internal/httputil"
	"github.com/fido-device-onboard/go-fdo/kex"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// stubTokenService provides a minimal token service for routing tests.
type stubTokenService struct{}

func (s *stubTokenService) NewToken(_ context.Context, _ protocol.Protocol) (string, error) {
	return "test-token", nil
}
func (s *stubTokenService) TokenContext(ctx context.Context, token string) context.Context {
	return ctx
}
func (s *stubTokenService) TokenFromContext(ctx context.Context) (string, bool) {
	return "test-token", true
}
func (s *stubTokenService) InvalidateToken(ctx context.Context) error {
	return nil
}

// stubResponder provides a minimal responder that returns a fixed response.
// It implements the CryptSession interface to satisfy the handler's type
// assertion for encrypted TO2 messages.
type stubResponder struct {
	lastMsgType uint8
}

func (s *stubResponder) Respond(_ context.Context, msgType uint8, _ io.Reader) (uint8, any) {
	s.lastMsgType = msgType
	// Return a non-encrypted response type so the handler doesn't try to
	// encrypt the response body (which would require a real kex.Session).
	// Protocol start messages return the next sequential type.
	return msgType + 1, nil
}

func (s *stubResponder) HandleError(_ context.Context, _ protocol.ErrorMessage) {}

// CryptSession satisfies the type assertion in the handler for encrypted
// TO2 message types. It returns an error, which causes the handler to
// write an error response rather than panic.
func (s *stubResponder) CryptSession(_ context.Context) (kex.Session, error) {
	return nil, fmt.Errorf("stub: no crypto session available")
}

func newRoutingHandler() (*fdo_http.Handler, *stubResponder, *stubResponder, *stubResponder, *stubResponder) {
	di := &stubResponder{}
	to0 := &stubResponder{}
	to1 := &stubResponder{}
	to2 := &stubResponder{}
	h := &fdo_http.Handler{
		Tokens:       &stubTokenService{},
		DIResponder:  di,
		TO0Responder: to0,
		TO1Responder: to1,
		TO2Responder: to2,
	}
	return h, di, to0, to1, to2
}

func makeRequest(method, path string, body []byte) *http.Request {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	} else {
		bodyReader = bytes.NewReader([]byte{0xf6}) // CBOR null
	}
	req, _ := http.NewRequest(method, path, bodyReader)
	req.ContentLength = int64(len(body))
	if body == nil {
		req.ContentLength = 1
	}
	return req
}

// TestRoutingV101Messages verifies that FDO 1.1 messages are correctly
// routed via /fdo/101/msg/{type} paths.
func TestRoutingV101Messages(t *testing.T) {
	tests := []struct {
		name    string
		msgType uint8
		path    string
	}{
		{"DI AppStart", 10, "/fdo/101/msg/10"},
		{"DI Done", 13, "/fdo/101/msg/13"},
		{"TO0 Hello", 20, "/fdo/101/msg/20"},
		{"TO0 AcceptOwner", 23, "/fdo/101/msg/23"},
		{"TO1 HelloRV", 30, "/fdo/101/msg/30"},
		{"TO1 RVRedirect", 33, "/fdo/101/msg/33"},
		{"TO2 HelloDevice", 60, "/fdo/101/msg/60"},
		{"TO2 Done2", 71, "/fdo/101/msg/71"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, _, _, _, _ := newRoutingHandler()
			rr := new(httputil.ResponseRecorder)
			body, _ := cbor.Marshal(nil)
			req := makeRequest(http.MethodPost, tt.path, body)
			handler.ServeHTTP(rr, req)
			resp := rr.Result()

			// Should get HTTP 200 (even if business logic is stub)
			// or 500 with error - the key point is NOT 404/405
			if resp.StatusCode == http.StatusNotFound {
				t.Errorf("path %s returned 404, expected routing to succeed", tt.path)
			}
			if resp.StatusCode == http.StatusMethodNotAllowed {
				t.Errorf("path %s returned 405, expected POST to be accepted", tt.path)
			}
		})
	}
}

// TestRoutingV200Messages verifies that FDO 2.0 messages are correctly
// routed via /fdo/200/msg/{type} paths.
func TestRoutingV200Messages(t *testing.T) {
	tests := []struct {
		name    string
		msgType uint8
		path    string
	}{
		{"TO2 HelloDeviceProbe", 80, "/fdo/200/msg/80"},
		{"TO2 HelloDeviceAck20", 81, "/fdo/200/msg/81"},
		{"TO2 ProveDevice20", 82, "/fdo/200/msg/82"},
		{"TO2 ProveOVHdr20", 83, "/fdo/200/msg/83"},
		{"TO2 GetOVNextEntry20", 84, "/fdo/200/msg/84"},
		{"TO2 OVNextEntry20", 85, "/fdo/200/msg/85"},
		{"TO2 DeviceSvcInfoRdy20", 86, "/fdo/200/msg/86"},
		{"TO2 SetupDevice20", 87, "/fdo/200/msg/87"},
		{"TO2 DeviceSvcInfo20", 88, "/fdo/200/msg/88"},
		{"TO2 OwnerSvcInfo20", 89, "/fdo/200/msg/89"},
		{"TO2 Done20", 90, "/fdo/200/msg/90"},
		{"TO2 DoneAck20", 91, "/fdo/200/msg/91"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, _, _, _, _ := newRoutingHandler()
			rr := new(httputil.ResponseRecorder)
			body, _ := cbor.Marshal(nil)
			req := makeRequest(http.MethodPost, tt.path, body)
			handler.ServeHTTP(rr, req)
			resp := rr.Result()

			if resp.StatusCode == http.StatusNotFound {
				t.Errorf("path %s returned 404, expected routing to succeed", tt.path)
			}
			if resp.StatusCode == http.StatusMethodNotAllowed {
				t.Errorf("path %s returned 405, expected POST to be accepted", tt.path)
			}
		})
	}
}

// TestRoutingVersionMismatch verifies that sending a v2.0 message type on
// the /fdo/101/ path (or vice versa) is rejected. The handler validates
// that the URL version matches the message type's intrinsic version.
func TestRoutingVersionMismatch(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		// v2.0 message types on v1.1 path
		{"v2.0 msg 80 on v1.1 path", "/fdo/101/msg/80"},
		{"v2.0 msg 85 on v1.1 path", "/fdo/101/msg/85"},
		{"v2.0 msg 91 on v1.1 path", "/fdo/101/msg/91"},

		// v1.1 message types on v2.0 path
		{"v1.1 msg 10 on v2.0 path", "/fdo/200/msg/10"},
		{"v1.1 msg 20 on v2.0 path", "/fdo/200/msg/20"},
		{"v1.1 msg 30 on v2.0 path", "/fdo/200/msg/30"},
		{"v1.1 msg 60 on v2.0 path", "/fdo/200/msg/60"},
		{"v1.1 msg 71 on v2.0 path", "/fdo/200/msg/71"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, _, _, _, _ := newRoutingHandler()
			rr := new(httputil.ResponseRecorder)
			body, _ := cbor.Marshal(nil)
			req := makeRequest(http.MethodPost, tt.path, body)
			handler.ServeHTTP(rr, req)
			resp := rr.Result()

			if resp.StatusCode == http.StatusOK {
				t.Errorf("path %s should be rejected due to version mismatch, got 200", tt.path)
			}

			// Should return 500 with error message
			if resp.StatusCode != http.StatusInternalServerError {
				t.Errorf("path %s: expected 500, got %d", tt.path, resp.StatusCode)
			}

			// Verify it's a CBOR error response
			msgType := resp.Header.Get("Message-Type")
			if msgType != strconv.Itoa(int(protocol.ErrorMsgType)) {
				t.Errorf("expected error message type %d, got %s", protocol.ErrorMsgType, msgType)
			}
		})
	}
}

// TestRoutingInvalidVersion verifies that unsupported FDO version numbers
// in the URL path are rejected.
func TestRoutingInvalidVersion(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"version 0", "/fdo/0/msg/10"},
		{"version 1", "/fdo/1/msg/10"},
		{"version 100", "/fdo/100/msg/10"},
		{"version 102", "/fdo/102/msg/10"},
		{"version 199", "/fdo/199/msg/10"},
		{"version 201", "/fdo/201/msg/80"},
		{"version 999", "/fdo/999/msg/10"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, _, _, _, _ := newRoutingHandler()
			rr := new(httputil.ResponseRecorder)
			body, _ := cbor.Marshal(nil)
			req := makeRequest(http.MethodPost, tt.path, body)
			handler.ServeHTTP(rr, req)
			resp := rr.Result()

			if resp.StatusCode == http.StatusOK {
				t.Errorf("path %s should be rejected for invalid version, got 200", tt.path)
			}
		})
	}
}

// TestRoutingInvalidPaths verifies that malformed URL paths are rejected.
func TestRoutingInvalidPaths(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"empty path", "/"},
		{"fdo only", "/fdo/"},
		{"missing msg segment", "/fdo/101/10"},
		{"wrong segment name", "/fdo/101/message/10"},
		{"extra path segments", "/fdo/101/msg/10/extra"},
		{"no message type", "/fdo/101/msg/"},
		{"non-numeric message type", "/fdo/101/msg/abc"},
		{"non-numeric version", "/fdo/abc/msg/10"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, _, _, _, _ := newRoutingHandler()
			rr := new(httputil.ResponseRecorder)
			body, _ := cbor.Marshal(nil)
			req := makeRequest(http.MethodPost, tt.path, body)
			handler.ServeHTTP(rr, req)
			resp := rr.Result()

			if resp.StatusCode == http.StatusOK {
				t.Errorf("path %s should be rejected, got 200", tt.path)
			}
		})
	}
}

// TestRoutingMethodNotAllowed verifies that non-POST methods are rejected.
func TestRoutingMethodNotAllowed(t *testing.T) {
	methods := []string{
		http.MethodGet,
		http.MethodPut,
		http.MethodDelete,
		http.MethodPatch,
		http.MethodHead,
		http.MethodOptions,
	}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			handler, _, _, _, _ := newRoutingHandler()
			rr := new(httputil.ResponseRecorder)
			body, _ := cbor.Marshal(nil)
			req := makeRequest(method, "/fdo/101/msg/10", body)
			handler.ServeHTTP(rr, req)
			resp := rr.Result()

			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("%s request: expected 405, got %d", method, resp.StatusCode)
			}
		})
	}
}

// TestRoutingResponseHeaders verifies that successful routing produces the
// expected response headers (Content-Type, Message-Type, Authorization).
func TestRoutingResponseHeaders(t *testing.T) {
	handler, _, _, _, _ := newRoutingHandler()
	rr := new(httputil.ResponseRecorder)
	body, _ := cbor.Marshal(nil)
	req := makeRequest(http.MethodPost, "/fdo/101/msg/10", body)
	handler.ServeHTTP(rr, req)
	resp := rr.Result()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Check Content-Type header
	ct := resp.Header.Get("Content-Type")
	if ct != "application/cbor" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/cbor")
	}

	// Check Message-Type header exists and is numeric
	mt := resp.Header.Get("Message-Type")
	if mt == "" {
		t.Error("Message-Type header is missing")
	} else if _, err := strconv.ParseUint(mt, 10, 8); err != nil {
		t.Errorf("Message-Type header %q is not a valid uint8", mt)
	}

	// Check Authorization header exists (token should be returned)
	auth := resp.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		t.Errorf("Authorization header = %q, expected Bearer prefix", auth)
	}
}

// TestRoutingV200ResponseHeaders verifies that v2.0 message routing also
// produces correct response headers.
func TestRoutingV200ResponseHeaders(t *testing.T) {
	handler, _, _, _, _ := newRoutingHandler()
	rr := new(httputil.ResponseRecorder)
	body, _ := cbor.Marshal(nil)
	req := makeRequest(http.MethodPost, "/fdo/200/msg/80", body)
	handler.ServeHTTP(rr, req)
	resp := rr.Result()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for v2.0 message, got %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if ct != "application/cbor" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/cbor")
	}
}
