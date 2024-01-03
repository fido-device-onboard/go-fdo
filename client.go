// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"io"
	"time"
)

// Protocol is the FDO specification-defined protocol.
type Protocol uint8

const (
	UnknownProtocol Protocol = iota
	DIProtocol
	TO0Protocol
	TO1Protocol
	TO2Protocol
	AnyProtocol // for error message types
)

// ProtocolOf returns the protocol a given message type belongs to.
func ProtocolOf(msgType uint8) Protocol {
	switch msgType {
	case 10, 11, 12, 13:
		return DIProtocol
	case 20, 21, 22, 23:
		return TO0Protocol
	case 30, 31, 32, 33:
		return TO1Protocol
	case 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71:
		return TO2Protocol
	case 255:
		return AnyProtocol
	default:
		return UnknownProtocol
	}
}

// Client implements methods for performing FDO protocols DI (non-normative),
// TO1, and TO2.
type Client struct {
	// Transport
	Transport Transport

	// Retry optionally sets a policy for retrying protocol messages.
	Retry RetryDecider
	// if c.Retry == nil {
	// 	c.Retry = neverRetry{}
	// }

	// TODO: DeviceCredential get/set interface, including sign/verify
	// and hmac/hmacverify abstractions

	// TODO: RVBypass settings

	// TODO: TO2 address list get/set interface

	// TODO: Map of registered FSIMs by name
}

// DeviceInitialization runs the DI protocol and has side effects of setting
// device credentials.
func (*Client) DeviceInitialization(ctx context.Context) error

// TransferOwnership1 runs the TO1 protocol and has side effects of setting the
// RV blob for TO2 addresses.
func (*Client) TransferOwnership1(ctx context.Context) error

// TransferOwnership2 runs the TO2 protocol and has side effects of performing
// FSIMs.
func (*Client) TransferOwnership2(ctx context.Context) error

// Transport abstracts the underlying TCP/HTTP/CoAP transport.
type Transport interface {
	Send(ctx context.Context, base string, msgType uint8, msg any) (respType uint8, _ io.ReadCloser, _ error)
}

// RetryDecider allows for deciding whether a retry should occur, based on the
// request's message type and the error response.
type RetryDecider interface {
	// ShouldRetry returns nil when a retry should not be attempted. Otherwise
	// it returns a non-nil channel. The channel will have exactly one value
	// sent on it and is not guaranteed to close.
	//
	// TODO: Return next set of options for RV?
	ShouldRetry(ErrorMessage) <-chan time.Time
}
