// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package serviceinfo

import (
	"context"
	"io"
)

// A Module handles a single service info key's moduleName (key format:
// "moduleName:messageName"). Any service info structs returned should be added
// to the send queue and processed before TO2 completes.
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
