// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package token implements all server state interfaces possible using a
// stateless token.
package token

import (
	"context"
	"crypto/x509"

	"github.com/fido-device-onboard/go-fdo"
)

// Service implements the fdo.TokenService interface and state interfaces
// that do not need to persist beyond a single protocol session.
type Service struct {
	HmacSecret []byte
}

var _ fdo.TokenService = (*Service)(nil)
var _ fdo.GUIDState = (*Service)(nil)
var _ fdo.VoucherCreationState = (*Service)(nil)

// NewToken initializes state for a given protocol and return the
// associated token.
func (s Service) NewToken(context.Context, fdo.Protocol) (string, error)

// TokenContext injects a context with a token value so that it may be used
// for any of the XXXState interfaces.
func (s Service) TokenContext(context.Context, string) context.Context

// TokenFromContext gets the token value from a context. This is useful,
// because some TokenServices may allow token mutation, such as in the case
// of token-encoded state (i.e. JWTs/CWTs).
func (s Service) TokenFromContext(context.Context) (string, bool)

// SetGUID sets the GUID for the current session.
func (s Service) SetGUID(context.Context, fdo.GUID) error

// GUID retrieves the GUID for the current session.
func (s Service) GUID(context.Context) (*fdo.GUID, error)

// NewDeviceCertChain creates a device certificate chain based on info
// provided in the (non-normative) DI.AppStart message and also stores it
// in session state.
func (s Service) NewDeviceCertChain(context.Context, fdo.DeviceMfgInfo) ([]*x509.Certificate, error)

// DeviceCertChain gets a device certificate chain from the current
// session.
func (s Service) DeviceCertChain(context.Context) ([]*x509.Certificate, error)

// SetIncompleteVoucherHeader stores an incomplete (missing HMAC) voucher
// header tied to a session.
func (s Service) SetIncompleteVoucherHeader(context.Context, *fdo.VoucherHeader) error

// IncompleteVoucherHeader gets an incomplete (missing HMAC) voucher header
// which has not yet been persisted.
func (s Service) IncompleteVoucherHeader(context.Context) (*fdo.VoucherHeader, error)
