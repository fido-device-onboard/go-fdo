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
	"github.com/fido-device-onboard/go-fdo/protocol"
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
type ErrUnsupportedKeyType protocol.KeyType

func (err ErrUnsupportedKeyType) Error() string {
	return "unsupported key type " + protocol.KeyType(err).String()
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
	SetTO0SignNonce(context.Context, protocol.Nonce) error

	// TO0SignNonce returns the Nonce expected in TO0.OwnerSign.
	TO0SignNonce(context.Context) (protocol.Nonce, error)
}

// TO1SessionState stores TO1 protocol state for a particular session.
type TO1SessionState interface {
	// SetTO1ProofNonce sets the Nonce expected in TO1.ProveToRV.
	SetTO1ProofNonce(context.Context, protocol.Nonce) error

	// TO1ProofNonce returns the Nonce expected in TO1.ProveToRV.
	TO1ProofNonce(context.Context) (protocol.Nonce, error)
}

// TO2SessionState stores TO2 protocol state for a particular session.
type TO2SessionState interface {
	// SetGUID associates a voucher GUID with a TO2 session.
	SetGUID(context.Context, protocol.GUID) error

	// GUID retrieves the GUID of the voucher associated with the session.
	GUID(context.Context) (protocol.GUID, error)

	// SetRvInfo stores the rendezvous instructions to store at the end of TO2.
	SetRvInfo(context.Context, [][]protocol.RvInstruction) error

	// RvInfo retrieves the rendezvous instructions to store at the end of TO2.
	RvInfo(context.Context) ([][]protocol.RvInstruction, error)

	// SetReplacementGUID stores the device GUID to persist at the end of TO2.
	SetReplacementGUID(context.Context, protocol.GUID) error

	// ReplacementGUID retrieves the device GUID to persist at the end of TO2.
	ReplacementGUID(context.Context) (protocol.GUID, error)

	// SetReplacementHmac stores the voucher HMAC to persist at the end of TO2.
	SetReplacementHmac(context.Context, protocol.Hmac) error

	// ReplacementHmac retrieves the voucher HMAC to persist at the end of TO2.
	ReplacementHmac(context.Context) (protocol.Hmac, error)

	// SetXSession updates the current key exchange/encryption session based on
	// an opaque "authorization" token.
	//
	// The Session value is not safe to use after the function returns.
	SetXSession(context.Context, kex.Suite, kex.Session) error

	// XSession returns the current key exchange/encryption session based on an
	// opaque "authorization" token.
	XSession(context.Context) (kex.Suite, kex.Session, error)

	// SetProveDeviceNonce stores the Nonce used in TO2.ProveDevice for use in
	// TO2.Done.
	SetProveDeviceNonce(context.Context, protocol.Nonce) error

	// ProveDeviceNonce returns the Nonce used in TO2.ProveDevice and TO2.Done.
	ProveDeviceNonce(context.Context) (protocol.Nonce, error)

	// SetSetupDeviceNonce stores the Nonce used in TO2.SetupDevice for use in
	// TO2.Done2.
	SetSetupDeviceNonce(context.Context, protocol.Nonce) error

	// SetupDeviceNonce returns the Nonce used in TO2.SetupDevice and
	// TO2.Done2.
	SetupDeviceNonce(context.Context) (protocol.Nonce, error)

	// SetMTU sets the max service info size the device may receive.
	SetMTU(context.Context, uint16) error

	// MTU returns the max service info size the device may receive.
	MTU(context.Context) (uint16, error)
}

// RendezvousBlobPersistentState maintains device to owner info state used in
// TO0 and TO1.
type RendezvousBlobPersistentState interface {
	// SetRVBlob sets the owner rendezvous blob for a device.
	SetRVBlob(context.Context, *Voucher, *cose.Sign1[protocol.To1d, []byte], time.Time) error

	// RVBlob returns the owner rendezvous blob for a device.
	RVBlob(context.Context, protocol.GUID) (*cose.Sign1[protocol.To1d, []byte], *Voucher, error)
}

// OwnerKeyPersistentState maintains the owner service keys.
type OwnerKeyPersistentState interface {
	// OwnerKey returns the private key matching a given key type and optionally
	// its certificate chain.
	OwnerKey(protocol.KeyType) (crypto.Signer, []*x509.Certificate, error)
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
	ReplaceVoucher(context.Context, protocol.GUID, *Voucher) error

	// RemoveVoucher untracks a voucher, possibly by deleting it or marking it
	// as removed, and returns it for extension.
	RemoveVoucher(context.Context, protocol.GUID) (*Voucher, error)

	// Voucher retrieves a voucher by GUID.
	Voucher(context.Context, protocol.GUID) (*Voucher, error)
}

// The following types are for optional server features.

// AutoExtend provides the necessary methods for automatically extending a
// device voucher upon the completion of DI.
type AutoExtend interface {
	// ManufacturerKey returns the signer of a given key type and its certificate
	// chain (required).
	ManufacturerKey(keyType protocol.KeyType) (crypto.Signer, []*x509.Certificate, error)

	// OwnerKey returns the private key matching a given key type and optionally
	// its certificate chain.
	OwnerKey(keyType protocol.KeyType) (crypto.Signer, []*x509.Certificate, error)
}

// AutoTO0 provides the necessary methods for setting a rendezvous blob upon
// device voucher auto-extension.
type AutoTO0 interface {
	// OwnerKey returns the private key matching a given key type and optionally
	// its certificate chain.
	OwnerKey(keyType protocol.KeyType) (crypto.Signer, []*x509.Certificate, error)

	// SetRVBlob sets the owner rendezvous blob for a device.
	SetRVBlob(context.Context, *Voucher, *cose.Sign1[protocol.To1d, []byte], time.Time) error
}
