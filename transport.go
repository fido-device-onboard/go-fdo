// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"io"

	"github.com/fido-device-onboard/go-fdo/kex"
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

func (p TransportProtocol) String() string {
	switch p {
	case TCPTransport:
		return "tcp"
	case TLSTransport:
		return "tls"
	case HTTPTransport:
		return "http"
	case CoAPTransport:
		return "coap"
	case HTTPSTransport:
		return "https"
	case CoAPSTransport:
		return "coaps"
	default:
		return "unknown"
	}
}

// Transport abstracts the underlying TCP/HTTP/CoAP transport for sending a
// message and receiving a response.
type Transport interface {
	// Send a message and receive a response. The response reader should always
	// be closed.
	Send(ctx context.Context, baseURL string, msgType uint8, msg any, sess kex.Session) (respType uint8, _ io.ReadCloser, _ error)
}
