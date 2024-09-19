// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package protocol

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
