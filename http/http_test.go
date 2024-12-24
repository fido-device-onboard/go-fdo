// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package http_test

import (
	"net/http"
	"testing"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/fdotest"
	fdo_http "github.com/fido-device-onboard/go-fdo/http"
	"github.com/fido-device-onboard/go-fdo/http/internal/httputil"
	"github.com/fido-device-onboard/go-fdo/protocol"
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

	t.Run("Without Debug", func(t *testing.T) {
		fdotest.RunClientTestSuite(t, fdotest.Config{
			NoDebug:      true,
			NewTransport: newTransport,
		})
	})

	t.Run("With Debug", func(t *testing.T) {
		fdotest.RunClientTestSuite(t, fdotest.Config{NewTransport: newTransport})
	})
}

type transport struct {
	T       *testing.T
	Handler http.Handler
}

// Assume request is well-formed and ignore timeouts, retries, etc.
func (tr *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	rr := new(httputil.ResponseRecorder)
	tr.Handler.ServeHTTP(rr, req)
	resp := rr.Result()
	resp.Request = req
	return resp, nil
}
