// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package serviceinfo

import (
	"context"
	"io"
)

// A Module handles a single service info key's moduleName (key format:
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
// Responses may not be sent immediately, as the receive queue in TO2 is
// processed in parallel and must be completed, potentially across multiple
// rounds of 68-69 messages, before sends may occur.
//
// Any error returned will cause an ErrorMessage to be sent and TO2 will fail.
// If a warning should be logged, this must be done within the handler.
type Module interface {
	// Transition sets the state of the module to active or inactive. Receive
	// and Respond will not be called unless Transition has been called at
	// least once and with the last input of true. Transition, as such, is only
	// a callback to allow setting up/tearing down state.
	Transition(active bool)

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
	Receive(ctx context.Context, moduleName, messageName string, messageBody io.Reader, respond func(message string) io.Writer) error
}

// UnknownModule handles receiving and responding to service info for an
// inactive or missing module.
//
// Section 3.8.3.1 says to ignore all messages for unknown modules, except
// message=active, which should respond CBOR false. The exceception to the
// exception is that devmod should always return active=true.
type UnknownModule struct{}

var _ Module = (*UnknownModule)(nil)

// Transition implements Module.
func (m UnknownModule) Transition(bool) {}

// Receive implements Module.
func (m UnknownModule) Receive(_ context.Context, _, _ string, messageBody io.Reader, _ func(string) io.Writer) error {
	// Ignore message and drain the body
	_, _ = io.Copy(io.Discard, messageBody)
	return nil
}

// UnsafeModule is optionally implemented by Modules in order to allow sending
// service info before reading the entire body of the received message. Doing
// so is unsafe, because the TO2 service info subprotocol lets each peer send
// as many service info KVs as it wants before allowing the other to respond.
//
// If service info is not immediately consumed, then responses cannot be sent
// over the wire, because the peer may have indicated IsMoreServiceInfo.
// Service info sent from an UnsafeModule will be buffered, but the buffer is
// not infinite, so the implementer must acknowledge that the implementation
// may cause deadlocks (or out-of-memory errors).
type UnsafeModule interface {
	ThisModuleMayCauseDeadlocks()
}
