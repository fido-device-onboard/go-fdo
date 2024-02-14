// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"crypto/x509"
	"io"
	"time"
)

// Server implements business logic handling for all FDO protocols.
type Server struct {
	// DeviceForInfo correlates a device certificate chain to info provided in
	// the DI.AppStart message.
	DeviceForInfo func(info any) ([]*x509.Certificate, error)
}

// Respond validates a request and returns the appropriate response message.
func (s *Server) Respond(ctx context.Context, token string, msgType uint8, msg io.Reader) (newToken string, respType uint8, resp any, err error) {
	ctx = contextWithErrMsg(ctx)

	if errMsg := errMsgFromContext(ctx); errMsg != nil {
		// Default to error code 500, error message of err parameter, and timestamp
		// of the current time
		if errMsg.Code == 0 {
			errMsg.Code = internalServerErrCode
		}
		if errMsg.ErrString == "" {
			errMsg.ErrString = err.Error()
		}
		if errMsg.Timestamp == 0 {
			errMsg.Timestamp = time.Now().Unix()
		}
		return "", 0, nil, errMsg
	}

	panic("unimplemented")
}
