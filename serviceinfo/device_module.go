// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package serviceinfo

import (
	"context"
	"io"
)

// MTUKey is the context key for the uint16 MTU value. See the description of
// DeviceModule.Receive.
type MTUKey struct{}

// A DeviceModule handles a single service info key's moduleName (key format:
// "moduleName:messageName"). "active" messages are automatically handled and
// do not result in a call to Receive method.
//
// Chunking is applied automatically, so large responses may be written without
// custom chunking code. Responses larger than the MTU will cause the marshaled
// payload to be split across multiple bstrs. The data within the bstrs must be
// concatenated at the receiver in order to reconstruct the payload and
// guarantee a valid CBOR object. When chunking occurs, the device sends
// IsMoreServiceInfo = true.
//
// Unchunking is automatic and applies the reverse process to the above. Note
// that this only occurs when IsMoreServiceInfo = true and the same message is
// sent multiple times in a row.
//
// MessageBody must be fully read before writing a response unless the module
// implements UnsafeModule. Writing before fully consuming the reader will case
// the writer to fail.
//
// Responses may be queued and not sent immediately, as the receive queue in
// TO2 may still be filling, potentially across multiple rounds of 68-69
// messages. Sends only occur once the peer has stopped indicating
// IsMoreServiceInfo.
//
// Any error returned will cause an ErrorMessage to be sent and TO2 will fail.
// If a warning should be logged, this must be done within the handler.
type DeviceModule interface {
	// Transition sets the state of the module to active or inactive. Receive
	// and Respond will not be called unless Transition has been called at
	// least once and with the last input of true. Transition, as such, is only
	// a callback to allow setting up/tearing down state.
	Transition(active bool) error

	// Receive handles received service info. When any message is received
	// multiple times, the values will automatically be concatenated. For
	// cumulative data, this means that large values like files can be read
	// from a single io.Reader. For repetitive discrete objects, a CBOR decoder
	// should be applied to the io.Reader and a stream of objects can be read.
	//
	// The respond callback allows the module to send any number of service
	// info KVs. A writer is provided, as automatic chunking of messages larger
	// than the MTU will be performed. However, there is no automatic batching
	// of writes into a single KV, so each Write will result in at least one
	// service info KV being sent (possibly in a larger group of KVs per FDO
	// message).
	//
	// The yield callback will cause the next service info to be sent in a new
	// message, regardless of how much space is left in the current device
	// service info array.
	//
	// For manual chunking using yield, it may be desirable to know the MTU.
	// The full negotiated MTU (not the current space left from the MTU) can be
	// acquired from `ctx.Value(serviceinfo.MTUKey{}).(uint16)`.
	Receive(ctx context.Context, messageName string, messageBody io.Reader, respond func(message string) io.Writer, yield func()) error

	// Yield indicates that all service info key value pairs have been received
	// from the owner module, possibly across multiple messages with
	// IsMoreServiceInfo set.
	//
	// The respond and yield callbacks behave the same as for Receive.
	Yield(ctx context.Context, respond func(message string) io.Writer, yield func()) error
}

// UnknownModule handles receiving and responding to service info for an
// inactive or missing module.
//
// Section 3.8.3.1 says to ignore all messages for unknown modules, except
// message=active, which should respond CBOR false. The exceception to the
// exception is that devmod should always return active=true.
type UnknownModule struct{}

var _ DeviceModule = (*UnknownModule)(nil)

// Transition implements DeviceModule.
func (m UnknownModule) Transition(bool) error { return nil }

// Receive implements DeviceModule.
func (m UnknownModule) Receive(_ context.Context, _ string, messageBody io.Reader, _ func(string) io.Writer, _ func()) error {
	// Ignore message and drain the body
	_, _ = io.Copy(io.Discard, messageBody)
	return nil
}

// Yield implements DeviceModule.
func (m UnknownModule) Yield(ctx context.Context, respond func(message string) io.Writer, yield func()) error {
	return nil
}
