// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"io"
)

// TransportProtocol is used to indicate which protocol to use in the
// Rendezvous blob.
type TransportProtocol uint8

// CDDL from spec:
//
//	TransportProtocol /= (
//	   ProtTCP:    1,     ;; bare TCP stream
//	   ProtTLS:    2,     ;; bare TLS stream
//	   ProtHTTP:   3,
//	   ProtCoAP:   4,
//	   ProtHTTPS:  5,
//	   ProtCoAPS:  6,
//	)
const (
	TCPTransport   TransportProtocol = 1
	TLSTransport   TransportProtocol = 2
	HTTPTransport  TransportProtocol = 3
	CoAPTransport  TransportProtocol = 4
	HTTPSTransport TransportProtocol = 5
	CoAPSTransport TransportProtocol = 6
)

// Transport abstracts the underlying TCP/HTTP/CoAP transport for sending a
// message and receiving a response.
type Transport interface {
	// Send a message and receive a response. The response reader should always
	// be closed.
	Send(ctx context.Context, baseURL string, msgType uint8, msg any) (respType uint8, _ io.ReadCloser, _ error)
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
