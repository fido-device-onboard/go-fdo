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

// Send implements fdo.Transport.
//
//nolint:gocyclo // Transport handler requires multiple message type cases
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
	var responder protocol.Responder
	proto := protocol.Of(msgType)
	var isProtocolStart bool
	switch proto {
	case protocol.DIProtocol:
		responder = t.DIResponder
		isProtocolStart = msgType == 10
	case protocol.TO0Protocol:
		responder = t.TO0Responder
		isProtocolStart = msgType == 20
	case protocol.TO1Protocol:
		responder = t.TO1Responder
		isProtocolStart = msgType == 30
	case protocol.TO2Protocol:
		responder = t.TO2Responder
		// TO2 starts at msg 60 (1.01) or msg 80 (2.0)
		isProtocolStart = msgType == protocol.TO2HelloDeviceMsgType || msgType == protocol.TO2HelloDeviceProbeMsgType
	case protocol.AnyProtocol:
		return 0, nil, nil
	default:
		return 0, nil, fmt.Errorf("unsupported msg type: %d", msgType)
	}
	if isProtocolStart {
		initToken, err := t.Tokens.NewToken(ctx, proto)
		if err != nil {
			return 0, nil, fmt.Errorf("error initializing token [protocol=%s]: %w", proto, err)
		}
		t.token = initToken
	}
	ctx = t.Tokens.TokenContext(ctx, t.token)

	respType, resp := responder.Respond(ctx, msgType, &msgBody)
	t.T.Logf("Response %d: %v", respType, tryDebugNotation(resp))
	t.token, _ = t.Tokens.TokenFromContext(ctx)
	t.prevMsg = msgType

	var respBody bytes.Buffer
	if err := cbor.NewEncoder(&respBody).Encode(resp); err != nil {
		return 0, nil, err
	}

	switch respType {
	case protocol.DIDoneMsgType, protocol.TO0AcceptOwnerMsgType, protocol.TO1RVRedirectMsgType,
		protocol.TO2Done2MsgType, protocol.TO2DoneAck20MsgType, protocol.ErrorMsgType:
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
