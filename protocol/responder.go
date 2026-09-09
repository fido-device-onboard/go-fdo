// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package protocol

import (
	"context"
	"io"
)

// Responder is implemented by *fdo.DIServer, *fdo.TO0Server, *fdo.TO1Server, and
// *fdo.TO2Server.
type Responder interface {
	// Respond validates a request and returns the appropriate response message.
	Respond(ctx context.Context, msgType uint8, msg io.Reader) (respType uint8, resp any)

	// HandleError performs session cleanup before the token is invalidated.
	HandleError(context.Context, ErrorMessage)
}

// TransportErrorHandler is an optional interface that Responders may implement
// to perform cleanup when the HTTP transport layer encounters an error (e.g.
// content too large, decryption failure). These errors bypass the normal
// Respond() path and therefore bypass any cleanup that Respond() would do.
//
// This is primarily useful for TO2Server, where modules may have created
// resources (upload directories, temp files) that need cleanup even when the
// transport layer fails.
type TransportErrorHandler interface {
	HandleTransportError(ctx context.Context, msgType uint8, err error)
}
