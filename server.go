// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"time"

	"github.com/fido-device-onboard/go-fdo/kex"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// DIServer implements the DI protocol.
type DIServer[T any] struct {
	Session  DISessionState
	Vouchers ManufacturerVoucherPersistentState

	// SignDeviceCertChain creates a device certificate chain based on info
	// provided in the DI.AppStart message.
	SignDeviceCertificate func(*T) ([]*x509.Certificate, error)

	// DeviceInfo returns the device info string to use for a given device,
	// based on its self-reported info and certificate chain (from
	// SignDeviceCertificate). The PublicKey returned is for the DI server and
	// must be the key that will be used for voucher extension.
	DeviceInfo func(context.Context, *T, []*x509.Certificate) (info string, mfgPubKey protocol.PublicKey, _ error)

	// Optional callback for before a new voucher is persisted.
	BeforeVoucherPersist func(context.Context, *Voucher) error

	// Optional callback for immediately after a new voucher is persisted.
	// There is no guarantee that the device will receive and process the Done
	// message (13) without error.
	AfterVoucherPersist func(context.Context, Voucher) error

	// Rendezvous directives
	RvInfo func(context.Context, *Voucher) ([][]protocol.RvInstruction, error)
}

// Respond validates a request and returns the appropriate response message.
func (s *DIServer[T]) Respond(ctx context.Context, msgType uint8, msg io.Reader) (respType uint8, resp any) {
	// Inject a mutable error into the context for error info capturing without
	// complex error wrapping or overburdened method signatures.
	ctx = contextWithErrMsg(ctx)
	captureMsgType(ctx, msgType)

	// Handle each message type
	var err error
	switch msgType {
	case protocol.DIAppStartMsgType:
		respType = protocol.DISetCredentialsMsgType
		resp, err = s.setCredentials(ctx, msg)
	case protocol.DISetHmacMsgType:
		respType = protocol.DIDoneMsgType
		resp, err = s.diDone(ctx, msg)
	}
	if err == nil {
		return respType, resp
	}

	// Default to error code 500, error message of err parameter, and timestamp
	// of the current time
	errMsg := errMsgFromContext(ctx)
	if errMsg.Code == 0 {
		errMsg.Code = protocol.InternalServerErrCode
	}
	if errMsg.ErrString == "" {
		errMsg.ErrString = err.Error()
	}
	if errMsg.Timestamp == 0 {
		errMsg.Timestamp = time.Now().Unix()
	}
	return protocol.ErrorMsgType, errMsg
}

// HandleError performs session cleanup before the token is invalidated.
func (s *DIServer[T]) HandleError(ctx context.Context, errMsg protocol.ErrorMessage) {}

// TO0Server implements the TO0 protocol.
type TO0Server struct {
	Session TO0SessionState
	RVBlobs RendezvousBlobPersistentState

	// AcceptVoucher is an optional function which, when given, is used to
	// determine whether to accept a voucher from a client and how long (TTL)
	// to retain a rendezvous blob for the owner service for the given voucher.
	//
	// If the TTL is 0, the request is rejected.
	//
	// If AcceptVoucher is not set, then all vouchers will be accepted and the
	// requested TTL will be used. It is expected that some other means of
	// authorization is used in this case.
	AcceptVoucher func(ctx context.Context, ov Voucher, requestedTTLSecs uint32) (ttlSecs uint32, err error)
}

// Respond validates a request and returns the appropriate response message.
func (s *TO0Server) Respond(ctx context.Context, msgType uint8, msg io.Reader) (respType uint8, resp any) {
	// Inject a mutable error into the context for error info capturing without
	// complex error wrapping or overburdened method signatures.
	ctx = contextWithErrMsg(ctx)
	captureMsgType(ctx, msgType)

	// Handle each message type
	var err error
	switch msgType {
	case protocol.TO0HelloMsgType:
		respType = protocol.TO0HelloAckMsgType
		resp, err = s.helloAck(ctx, msg)
	case protocol.TO0OwnerSignMsgType:
		respType = protocol.TO0AcceptOwnerMsgType
		resp, err = s.acceptOwner(ctx, msg)
	}
	if err == nil {
		return respType, resp
	}

	// Default to error code 500, error message of err parameter, and timestamp
	// of the current time
	errMsg := errMsgFromContext(ctx)
	if errMsg.Code == 0 {
		errMsg.Code = protocol.InternalServerErrCode
	}
	if errMsg.ErrString == "" {
		errMsg.ErrString = err.Error()
	}
	if errMsg.Timestamp == 0 {
		errMsg.Timestamp = time.Now().Unix()
	}
	return protocol.ErrorMsgType, errMsg
}

// HandleError performs session cleanup before the token is invalidated.
func (s *TO0Server) HandleError(ctx context.Context, errMsg protocol.ErrorMessage) {}

// TO1Server implements the TO1 protocol.
type TO1Server struct {
	Session TO1SessionState
	RVBlobs RendezvousBlobPersistentState
}

// Respond validates a request and returns the appropriate response message.
func (s *TO1Server) Respond(ctx context.Context, msgType uint8, msg io.Reader) (respType uint8, resp any) {
	// Inject a mutable error into the context for error info capturing without
	// complex error wrapping or overburdened method signatures.
	ctx = contextWithErrMsg(ctx)
	captureMsgType(ctx, msgType)

	// Handle each message type
	var err error
	switch msgType {
	case protocol.TO1HelloRVMsgType:
		respType = protocol.TO1HelloRVAckMsgType
		resp, err = s.helloRVAck(ctx, msg)
	case protocol.TO1ProveToRVMsgType:
		respType = protocol.TO1RVRedirectMsgType
		resp, err = s.rvRedirect(ctx, msg)
	}
	if err == nil {
		return respType, resp
	}

	// Default to error code 500, error message of err parameter, and timestamp
	// of the current time
	errMsg := errMsgFromContext(ctx)
	if errMsg.Code == 0 {
		errMsg.Code = protocol.InternalServerErrCode
	}
	if errMsg.ErrString == "" {
		errMsg.ErrString = err.Error()
	}
	if errMsg.Timestamp == 0 {
		errMsg.Timestamp = time.Now().Unix()
	}
	return protocol.ErrorMsgType, errMsg
}

// HandleError performs session cleanup before the token is invalidated.
func (s *TO1Server) HandleError(ctx context.Context, errMsg protocol.ErrorMessage) {}

// TO2Server implements the TO2 protocol.
type TO2Server struct {
	Session   TO2SessionState
	Modules   serviceinfo.ModuleStateMachine
	Vouchers  OwnerVoucherPersistentState
	Devices   OwnerDevicePersistentState
	OwnerKeys OwnerKeyPersistentState

	// Choose the replacement rendezvous directives based on the current
	// voucher of the onboarding device.
	RvInfo func(context.Context, Voucher) ([][]protocol.RvInstruction, error)

	// ReuseCredential, if not nil, will be called to determine whether to
	// apply the Credential Reuse Protocol based on the current voucher of an
	// onboarding device.
	ReuseCredential func(context.Context, Voucher) (bool, error)

	// VerifyVoucher, if not nil, will be called before creating and responding
	// with a TO2.ProveOVHdr message. Any error will cause TO2 to fail with a
	// not found status code.
	//
	// If VerifyVoucher is nil, the default behavior is to reject all vouchers
	// with zero extensions.
	VerifyVoucher func(context.Context, Voucher) error

	// MaxDeviceServiceInfoSize configures the maximum size service info that
	// Owner can receive and that the device should send. If left unset, then
	// DefaultMTU is used.
	//
	// Setting this configuration does not actually enforce that the device
	// does not send larger service info. The server transport should be
	// configured to only read data of a maximum size. Choosing a lower value
	// is useful when it can help a well-behaved device communicate faster over
	// a well understood network.
	MaxDeviceServiceInfoSize func(context.Context, Voucher) (uint16, error)
}

// Resell implements the FDO Resale Protocol by removing a voucher from
// ownership, extending it to a new owner, and then returning it for
// out-of-band transport.
func (s *TO2Server) Resell(ctx context.Context, guid protocol.GUID, nextOwner crypto.PublicKey, extra map[int][]byte) (*Voucher, error) {
	// Remove voucher from ownership of this service
	ov, err := s.Vouchers.RemoveVoucher(ctx, guid)
	if err != nil {
		return nil, fmt.Errorf("error untracking voucher for resale: %w", err)
	}

	// Get current owner key
	ownerPubKey := ov.Header.Val.ManufacturerKey
	if len(ov.Entries) > 0 {
		ownerPubKey = ov.Entries[len(ov.Entries)-1].Payload.Val.PublicKey
	}
	ownerKey, _, err := s.OwnerKeys.OwnerKey(ctx, ownerPubKey.Type, ownerPubKey.RsaBits())
	if err != nil {
		_ = s.Vouchers.AddVoucher(ctx, ov)
		return nil, fmt.Errorf("error getting key used to sign voucher: %w", err)
	}

	// Extend voucher
	var extended *Voucher
	switch nextOwner := nextOwner.(type) {
	case *rsa.PublicKey:
		extended, err = ExtendVoucher(ov, ownerKey, nextOwner, extra)
	case *ecdsa.PublicKey:
		extended, err = ExtendVoucher(ov, ownerKey, nextOwner, extra)
	case []*x509.Certificate:
		extended, err = ExtendVoucher(ov, ownerKey, nextOwner, extra)
	default:
		err = fmt.Errorf("unsupported key type: %T", nextOwner)
	}
	if err != nil {
		_ = s.Vouchers.AddVoucher(ctx, ov)
		return nil, fmt.Errorf("error extending voucher to new owner: %w", err)
	}

	return extended, nil
}

// Respond validates a request and returns the appropriate response message.
func (s *TO2Server) Respond(ctx context.Context, msgType uint8, msg io.Reader) (respType uint8, resp any) {
	// Inject a mutable error into the context for error info capturing without
	// complex error wrapping or overburdened method signatures.
	ctx = contextWithErrMsg(ctx)
	captureMsgType(ctx, msgType)

	// Handle each message type
	var err error
	switch msgType {
	case protocol.TO2HelloDeviceMsgType:
		respType = protocol.TO2ProveOVHdrMsgType
		resp, err = s.proveOVHdr(ctx, msg)
	case protocol.TO2GetOVNextEntryMsgType:
		respType = protocol.TO2OVNextEntryMsgType
		resp, err = s.ovNextEntry(ctx, msg)
	case protocol.TO2ProveDeviceMsgType:
		respType = protocol.TO2SetupDeviceMsgType
		resp, err = s.setupDevice(ctx, msg)
	case protocol.TO2DeviceServiceInfoReadyMsgType:
		respType = protocol.TO2OwnerServiceInfoReadyMsgType
		resp, err = s.ownerServiceInfoReady(ctx, msg)
	case protocol.TO2DeviceServiceInfoMsgType:
		respType = protocol.TO2OwnerServiceInfoMsgType
		resp, err = s.ownerServiceInfo(ctx, msg)
		if err != nil {
			s.Modules.CleanupModules(ctx)
		}
	case protocol.TO2DoneMsgType:
		s.Modules.CleanupModules(ctx)
		respType = protocol.TO2Done2MsgType
		resp, err = s.to2Done2(ctx, msg)
	}

	// Return response on success
	if err == nil {
		return respType, resp
	}

	// Default to error code 500, error message of err parameter, and timestamp
	// of the current time
	errMsg := errMsgFromContext(ctx)
	if errMsg.Code == 0 {
		errMsg.Code = protocol.InternalServerErrCode
	}
	if errMsg.ErrString == "" {
		errMsg.ErrString = err.Error()
	}
	if errMsg.Timestamp == 0 {
		errMsg.Timestamp = time.Now().Unix()
	}
	return protocol.ErrorMsgType, errMsg
}

// CryptSession returns the current encryption session.
func (s *TO2Server) CryptSession(ctx context.Context) (kex.Session, error) {
	_, sess, err := s.Session.XSession(ctx)
	return sess, err
}

// HandleError performs session cleanup before the token is invalidated.
func (s *TO2Server) HandleError(ctx context.Context, errMsg protocol.ErrorMessage) {
	// This should only be applicable if errMsg.PrevMsgType == 69, but the
	// device reported error message cannot be completely trusted
	s.Modules.CleanupModules(ctx)
}
