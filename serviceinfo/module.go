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
	// Receive handles received service info. When any message is received
	// multiple times, the values will automatically be concatenated. For
	// cumulative data, this means that large values like files can be read
	// from a single io.Reader. For repetitive discrete objects, a CBOR decoder
	// should be applied to the io.Reader and a stream of objects can be read.
	Receive(ctx context.Context, moduleName, messageName string, messageBody io.Reader) error

	// Respond is called after all info is received and ReceiveInfo has
	// completed for every message. The Module is given an opportunity to send
	// any number of service info KVs. A writer is provided, as automatic
	// chunking of messages larger than the MTU will be performed. However,
	// there is no automatic batching of writes into a single KV, so each Write
	// will result in at least one service info KV being sent (possibly in a
	// larger group of KVs per FDO message).
	Respond(ctx context.Context, sendInfo func(message string) io.Writer) error
}
