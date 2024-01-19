// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package http

import (
	"context"
	"net/http"

	"github.com/fido-device-onboard/go-fdo"
)

// Server abstracts the underlying TCP/HTTP/CoAP transport for receiving a
// message and sending a response.
type Server struct {
	//nolint:unused
	srv http.Server
}

// Receive blocks until it accepts a new inbound connection. It is expected
// that handling the connection will occur in another goroutine and once
// the message is parsed the Responder will be used to perform the business
// logic. When complete, the chan must be closed.
func (s *Server) Receive(ctx context.Context, r fdo.Responder, done chan<- struct{}) {
	// TODO: implement
	panic("unimplemented")
}
