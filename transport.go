// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"io"
)

// Transport abstracts the underlying TCP/HTTP/CoAP transport for sending a
// message and receiving a response.
type Transport interface {
	// Send a message and receive a response. The response reader should always
	// be closed.
	Send(ctx context.Context, baseURL string, msgType uint8, msg any) (respType uint8, _ io.ReadCloser, _ error)

	// ResetContext clears the protocol state, e.g. the session authorization
	// token.
	ResetContext(Protocol)
}

// ServerTransport abstracts the underlying TCP/HTTP/CoAP transport for
// receiving a message and sending a response.
type ServerTransport interface {
	// Receive blocks until it accepts a new inbound connection. It is expected
	// that handling the connection will occur in another goroutine and once
	// the message is parsed the Responder will be used to perform the business
	// logic. When complete, the chan must be closed.
	Receive(context.Context, Responder, chan<- struct{})
}
