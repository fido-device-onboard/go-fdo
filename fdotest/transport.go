// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdotest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cbor/cdn"
	"github.com/fido-device-onboard/go-fdo/custom"
	"github.com/fido-device-onboard/go-fdo/kex"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// Transport for tests, directly calling the server's responder. No encryption
// is used, but key exchange is still performed.
type Transport struct {
	T *testing.T

	Tokens protocol.TokenService

	DIResponder  *fdo.DIServer[custom.DeviceMfgInfo]
	TO0Responder *fdo.TO0Server
	TO1Responder *fdo.TO1Server
	TO2Responder *fdo.TO2Server

	// internal state

	token   string
	prevMsg uint8
}

// responderForMessage returns the protocol responder and whether the message
// starts a new protocol session. A nil responder signals AnyProtocol.
func (t *Transport) responderForMessage(msgType uint8) (protocol.Responder, bool, error) {
	switch protocol.Of(msgType) {
	case protocol.DIProtocol:
		return t.DIResponder, msgType == 10, nil
	case protocol.TO0Protocol:
		return t.TO0Responder, msgType == 20, nil
	case protocol.TO1Protocol:
		return t.TO1Responder, msgType == 30, nil
	case protocol.TO2Protocol:
		return t.TO2Responder, protocol.IsProtocolStart(msgType), nil
	case protocol.AnyProtocol:
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("unsupported msg type: %d", msgType)
	}
}

// Send implements fdo.Transport.
func (t *Transport) Send(ctx context.Context, msgType uint8, msg any, sess kex.Session) (uint8, io.ReadCloser, error) {
	select {
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	default:
	}

	var msgBody bytes.Buffer
	if err := cbor.NewEncoder(&msgBody).Encode(msg); err != nil {
		return 0, nil, err
	}

	if msgType < t.prevMsg || protocol.Of(t.prevMsg) != protocol.Of(msgType) {
		t.token = ""
	}

	t.T.Logf("Request %d: %v", msgType, tryDebugNotation(msg))
	responder, isProtocolStart, err := t.responderForMessage(msgType)
	if err != nil {
		return 0, nil, err
	}
	if responder == nil {
		return 0, nil, nil
	}
	if isProtocolStart {
		initToken, err := t.Tokens.NewToken(ctx, protocol.Of(msgType))
		if err != nil {
			return 0, nil, fmt.Errorf("error initializing token [protocol=%s]: %w", protocol.Of(msgType), err)
		}
		t.token = initToken
	}
	ctx = t.Tokens.TokenContext(ctx, t.token)

	// Inject FDO version into context based on the message type. In
	// production the HTTP handler does this from the URL path, but the
	// test transport bypasses the handler.
	ctx = protocol.ContextWithVersion(ctx, protocol.VersionOf(msgType))

	respType, resp := responder.Respond(ctx, msgType, &msgBody)
	t.T.Logf("Response %d: %v", respType, tryDebugNotation(resp))
	t.token, _ = t.Tokens.TokenFromContext(ctx)
	t.prevMsg = msgType

	var respBody bytes.Buffer
	if err := cbor.NewEncoder(&respBody).Encode(resp); err != nil {
		return 0, nil, err
	}

	switch respType {
	case 13, 23, 33, 71, 91, protocol.ErrorMsgType:
		if err := t.Tokens.InvalidateToken(t.Tokens.TokenContext(context.Background(), t.token)); err != nil {
			t.T.Logf("error invalidating token: %v", err)
		}
	}

	return respType, io.NopCloser(&respBody), nil
}

func tryDebugNotation(v any) any {
	b, err := cbor.Marshal(v)
	if err != nil {
		return v
	}
	d, err := cdn.FromCBOR(b)
	if err != nil {
		return v
	}
	return d
}
