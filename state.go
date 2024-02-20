// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"crypto/x509"
)

/*
	All of the interfaces in this file should be implemented with the same
	logical backend. This is because all of the interfaces share the same
	concept of tokens, including how to set/fetch them from [context.Context]
	and their meaning as a key.

	This is not a strict requirement and it should be possible to have a generic
	random session ID implemented by TokenService and XXXState interfaces
	correlate this random identifier to internal indices.
*/

// TokenService maintains state related to the authorization header or similar
// token. The purpose of the token is to link API calls to their protocol
// context within the message stream defined by the FIDO Device Onboard
// Protocols. The handler for a subsequent message can find this stored state
// by looking it up using the token as a key.
type TokenService interface {
	// NewToken initializes state for a given protocol and return the
	// associated token.
	NewToken(context.Context, Protocol) (string, error)

	// TokenContext injects a context with a token value so that it may be used
	// for any of the XXXState interfaces.
	TokenContext(context.Context, string) context.Context

	// TokenFromContext gets the token value from a context. This is useful,
	// because some TokenServices may allow token mutation, such as in the case
	// of token-encoded state (i.e. JWTs/CWTs).
	TokenFromContext(context.Context) (string, bool)
}

// GUIDState maintains the GUID of the requester. Unlike some other states,
// which may often be backed by a database for persistence and horizontal
// scaling, GuidState is a good candidate for implementing with MAC'd
// "stateless" tokens.
type GUIDState interface {
	// SetGUID sets the GUID for the current session.
	SetGUID(context.Context, GUID) error

	// GUID retrieves the GUID for the current session.
	GUID(context.Context) (*GUID, error)
}

// VoucherCreationState maintains incomplete voucher state. This state is only
// used for the DI protocol.
type VoucherCreationState interface {
	// NewDeviceCertChain creates a device certificate chain based on info
	// provided in the (non-normative) DI.AppStart message and also stores it
	// in session state.
	NewDeviceCertChain(context.Context, DeviceMfgInfo) ([]*x509.Certificate, error)

	// DeviceCertChain gets a device certificate chain from the current
	// session.
	DeviceCertChain(context.Context) ([]*x509.Certificate, error)

	// SetIncompleteVoucherHeader stores an incomplete (missing HMAC) voucher
	// header tied to a session.
	SetIncompleteVoucherHeader(context.Context, *VoucherHeader) error

	// IncompleteVoucherHeader gets an incomplete (missing HMAC) voucher header
	// which has not yet been persisted.
	IncompleteVoucherHeader(context.Context) (*VoucherHeader, error)
}

// VoucherState maintains complete voucher state. This state is used in the DI,
// TO0, TO1, and TO2 protocols.
type VoucherState interface {
	// NewVoucher creates and stores a new voucher.
	NewVoucher(context.Context, *Voucher) error

	// Voucher retrieves a voucher by GUID.
	Voucher(context.Context, GUID) (*Voucher, error)
}
