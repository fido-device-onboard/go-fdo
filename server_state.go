// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"crypto"
	"crypto/x509"

	"github.com/fido-device-onboard/go-fdo/kex"
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

// VoucherProofState maintains the voucher association of a TO2 session while
// messages are being passed to
type VoucherProofState interface {
	// SetGUID associates a voucher GUID with a TO2 session.
	SetGUID(context.Context, GUID) error

	// GUID retrieves the GUID of the voucher associated with the session.
	GUID(context.Context) (GUID, error)
}

// VoucherPersistentState maintains complete voucher state. This state is used
// in the DI, TO0, TO1, and TO2 protocols.
type VoucherPersistentState interface {
	// NewVoucher creates and stores a new voucher.
	NewVoucher(context.Context, *Voucher) error

	// ReplaceVoucher stores a new voucher, possibly deleting or marking the
	// previous voucher as replaced.
	ReplaceVoucher(context.Context, GUID, *Voucher) error

	// Voucher retrieves a voucher by GUID.
	Voucher(context.Context, GUID) (*Voucher, error)
}

// VoucherReplacementState maintains the replacement info for a device
// performing TO2 before the new voucher is persisted.
type VoucherReplacementState interface {
	// SetReplacementGUID stores the device GUID to persist at the end of TO2.
	SetReplacementGUID(context.Context, GUID) error

	// ReplacementGUID retrieves the device GUID to persist at the end of TO2.
	ReplacementGUID(context.Context) (GUID, error)

	// SetReplacementHmac stores the voucher HMAC to persist at the end of TO2.
	SetReplacementHmac(context.Context, Hmac) error

	// ReplacementHmac retrieves the voucher HMAC to persist at the end of TO2.
	ReplacementHmac(context.Context) (Hmac, error)
}

// KeyExchangeState maintains the current key exchange/encryption session for
// TO2 after message 64.
type KeyExchangeState interface {
	// SetSession updates the current key exchange/encryption session based on
	// an opaque "authorization" token.
	SetSession(context.Context, kex.Suite, kex.Session) error

	// Session returns the current key exchange/encryption session based on an
	// opaque "authorization" token.
	Session(context.Context, string) (kex.Suite, kex.Session, error)
}

// NonceState tracks the nonces which are used... more than once... across a
// single protocol session.
type NonceState interface {
	// SetProveDeviceNonce stores the Nonce used in TO2.ProveDevice for use in
	// TO2.Done.
	SetProveDeviceNonce(context.Context, Nonce) error

	// ProveDeviceNonce returns the Nonce used in TO2.ProveDevice and TO2.Done.
	ProveDeviceNonce(context.Context) (Nonce, error)

	// SetSetupDeviceNonce stores the Nonce used in TO2.SetupDevice for use in
	// TO2.Done2.
	SetSetupDeviceNonce(context.Context, Nonce) error

	// SetupDeviceNonce returns the Nonce used in TO2.SetupDevice and
	// TO2.Done2.
	SetupDeviceNonce(context.Context) (Nonce, error)
}

// OwnerKeyPersistentState maintains the owner service keys.
type OwnerKeyPersistentState interface {
	// Signer returns the private key matching a given key type.
	Signer(KeyType) (crypto.Signer, bool)
}

// ServiceInfoState managers owner service info state, including settings such
// as MTU.
type ServiceInfoState interface {
	// SetMTU sets the max service info size the device may receive.
	SetMTU(context.Context, uint16) error

	// MTU returns the max service info size the device may receive.
	MTU(context.Context) (uint16, error)
}
