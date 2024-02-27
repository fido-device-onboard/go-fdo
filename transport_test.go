// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo_test

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/kex"
)

// Transport for tests, directly calling the server's responder. No encryption
// is used, but key exchange is still performed.
type Transport struct {
	// Server under test
	Responder interface {
		Respond(context.Context, string, uint8, io.Reader) (string, uint8, any)
	}
	T *testing.T

	// internal state

	token   string
	prevMsg uint8
}

// Send implements fdo.Transport.
func (t *Transport) Send(ctx context.Context, baseURL string, msgType uint8, msg any, sess kex.Session) (uint8, io.ReadCloser, error) {
	var msgBody bytes.Buffer
	if err := cbor.NewEncoder(&msgBody).Encode(msg); err != nil {
		return 0, nil, err
	}

	if msgType < t.prevMsg || fdo.ProtocolOf(t.prevMsg) != fdo.ProtocolOf(msgType) {
		t.token = ""
	}

	t.T.Logf("Request %d: %v", msgType, msg)
	newToken, respType, resp := t.Responder.Respond(ctx, t.token, msgType, &msgBody)
	t.T.Logf("Response %d: %v", respType, resp)
	t.token = newToken
	t.prevMsg = msgType

	var respBody bytes.Buffer
	if err := cbor.NewEncoder(&respBody).Encode(resp); err != nil {
		return 0, nil, err
	}

	return respType, io.NopCloser(&respBody), nil
}
