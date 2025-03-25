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
