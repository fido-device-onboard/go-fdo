// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"io"

	"github.com/fido-device-onboard/go-fdo/kex"
)

// Transport abstracts the underlying TCP/HTTP/CoAP transport for sending a
// message and receiving a response.
type Transport interface {
	// Send a message and receive a response. The response reader should always
	// be closed.
	Send(ctx context.Context, msgType uint8, msg any, sess kex.Session) (respType uint8, _ io.ReadCloser, _ error)
}
