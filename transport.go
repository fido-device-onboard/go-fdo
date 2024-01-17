// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"io"
)

// Transport abstracts the underlying TCP/HTTP/CoAP transport.
type Transport interface {
	Send(ctx context.Context, msgType uint8, msg any) (respType uint8, _ io.ReadCloser, _ error)
}
