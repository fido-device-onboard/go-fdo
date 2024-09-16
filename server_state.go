// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/fido-device-onboard/go-fdo/cose"
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

// ErrInvalidSession is used when the token is invalid or the backend fails
// during validation.
var ErrInvalidSession = fmt.Errorf("invalid session")

// ErrNotFound is used when the resource does not exist for the session.
var ErrNotFound = fmt.Errorf("not found")

// ErrUnsupportedKeyType is used when no key of the given type has been added
// to the server.
type ErrUnsupportedKeyType KeyType

func (err ErrUnsupportedKeyType) Error() string {
	return "unsupported key type " + KeyType(err).String()
}

// TokenService maintains state related to the authorization header or similar
// token. The purpose of the token is to link API calls to their protocol
// context within the message stream defined by the FIDO Device Onboard
// Protocols. The handler for a subsequent message can find this stored state
// by looking it up using the token as a key.
type TokenService interface {
	// NewToken initializes state for a given protocol and return the
	// associated token.
	NewToken(context.Context, Protocol) (string, error)

	// InvalidateToken destroys the state associated with a given token.
	InvalidateToken(context.Context) error

	// TokenContext injects a context with a token value so that it may be used
	// for any of the XXXState interfaces.
	TokenContext(context.Context, string) context.Context

	// TokenFromContext gets the token value from a context. This is useful,
	// because some TokenServices may allow token mutation, such as in the case
	// of token-encoded state (i.e. JWTs/CWTs).
	TokenFromContext(context.Context) (string, bool)
}

// DISessionState stores DI protocol state for a particular session.
type DISessionState interface {
	// SetDeviceCertChain sets the device certificate chain generated from
	// DI.AppStart info.
	SetDeviceCertChain(context.Context, []*x509.Certificate) error

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

// TO0SessionState stores TO0 protocol state for a particular session.
type TO0SessionState interface {
	// SetTO0SignNonce sets the Nonce expected in TO0.OwnerSign.
	SetTO0SignNonce(context.Context, Nonce) error

	// TO0SignNonce returns the Nonce expected in TO0.OwnerSign.
	TO0SignNonce(context.Context) (Nonce, error)
}

// TO1SessionState stores TO1 protocol state for a particular session.
type TO1SessionState interface {
	// SetTO1ProofNonce sets the Nonce expected in TO1.ProveToRV.
	SetTO1ProofNonce(context.Context, Nonce) error

	// TO1ProofNonce returns the Nonce expected in TO1.ProveToRV.
	TO1ProofNonce(context.Context) (Nonce, error)
}

// TO2SessionState stores TO2 protocol state for a particular session.
type TO2SessionState interface {
	// SetGUID associates a voucher GUID with a TO2 session.
	SetGUID(context.Context, GUID) error

	// GUID retrieves the GUID of the voucher associated with the session.
	GUID(context.Context) (GUID, error)

	// SetRvInfo stores the rendezvous instructions to store at the end of TO2.
	SetRvInfo(context.Context, [][]RvInstruction) error

	// RvInfo retrieves the rendezvous instructions to store at the end of TO2.
	RvInfo(context.Context) ([][]RvInstruction, error)

	// SetReplacementGUID stores the device GUID to persist at the end of TO2.
	SetReplacementGUID(context.Context, GUID) error

	// ReplacementGUID retrieves the device GUID to persist at the end of TO2.
	ReplacementGUID(context.Context) (GUID, error)

	// SetReplacementHmac stores the voucher HMAC to persist at the end of TO2.
	SetReplacementHmac(context.Context, Hmac) error

	// ReplacementHmac retrieves the voucher HMAC to persist at the end of TO2.
	ReplacementHmac(context.Context) (Hmac, error)

	// SetXSession updates the current key exchange/encryption session based on
	// an opaque "authorization" token.
	SetXSession(context.Context, kex.Suite, kex.Session) error

	// XSession returns the current key exchange/encryption session based on an
	// opaque "authorization" token.
	XSession(context.Context) (kex.Suite, kex.Session, error)

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

	// SetMTU sets the max service info size the device may receive.
	SetMTU(context.Context, uint16) error

	// MTU returns the max service info size the device may receive.
	MTU(context.Context) (uint16, error)
}

// RendezvousBlobPersistentState maintains device to owner info state used in
// TO0 and TO1.
type RendezvousBlobPersistentState interface {
	// SetRVBlob sets the owner rendezvous blob for a device.
	SetRVBlob(context.Context, *Voucher, *cose.Sign1[To1d, []byte], time.Time) error

	// RVBlob returns the owner rendezvous blob for a device.
	RVBlob(context.Context, GUID) (*cose.Sign1[To1d, []byte], *Voucher, error)
}

// OwnerKeyPersistentState maintains the owner service keys.
type OwnerKeyPersistentState interface {
	// OwnerKey returns the private key matching a given key type and optionally
	// its certificate chain.
	OwnerKey(KeyType) (crypto.Signer, []*x509.Certificate, error)
}

// ManufacturerVoucherPersistentState maintains vouchers created during DI
// which have not yet been extended.
type ManufacturerVoucherPersistentState interface {
	// NewVoucher creates and stores a voucher for a newly initialized device.
	// Note that the voucher may have entries if the server was configured for
	// auto voucher extension.
	NewVoucher(context.Context, *Voucher) error
}

// OwnerVoucherPersistentState maintains vouchers owned by the service.
type OwnerVoucherPersistentState interface {
	// AddVoucher stores the voucher of a device owned by the service.
	AddVoucher(context.Context, *Voucher) error

	// ReplaceVoucher stores a new voucher, possibly deleting or marking the
	// previous voucher as replaced.
	ReplaceVoucher(context.Context, GUID, *Voucher) error

	// RemoveVoucher untracks a voucher, possibly by deleting it or marking it
	// as removed, and returns it for extension.
	RemoveVoucher(context.Context, GUID) (*Voucher, error)

	// Voucher retrieves a voucher by GUID.
	Voucher(context.Context, GUID) (*Voucher, error)
}
