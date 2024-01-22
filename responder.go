// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"crypto/x509"
)

// Responder handles the business logic of responding to FDO messages,
// regardless of the underlying server transport.
type Responder struct {
	// DeviceForInfo correlates a device certificate chain to info provided in
	// the DI.AppStart message.
	DeviceForInfo func(info any) ([]*x509.Certificate, error)
}

// Respond validates a request and returns the appropriate response message.
func (r *Responder) Respond(ctx context.Context, msgType uint8, msg any) (respType uint8, resp any, _ error) {
	panic("unimplemented")
}
