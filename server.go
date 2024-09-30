// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"time"

	"github.com/fido-device-onboard/go-fdo/kex"
	"github.com/fido-device-onboard/go-fdo/plugin"
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
	// based on its self-reported info and certificate chain.
	DeviceInfo func(context.Context, *T, []*x509.Certificate) (string, protocol.KeyType, protocol.KeyEncoding, error)

	// When set, new vouchers will be extended using the appropriate owner key.
	AutoExtend AutoExtend

	// When set, new vouchers will be registered for rendezvous.
	AutoTO0      AutoTO0
	AutoTO0Addrs []protocol.RvTO2Addr

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

// TO0Server implements the TO0 protocol.
type TO0Server struct {
	Session TO0SessionState
	RVBlobs RendezvousBlobPersistentState

	// AcceptVoucher is an optional function which, when given, is used to
	// determine whether to accept a voucher from a client.
	//
	// If AcceptVoucher is not set, then all vouchers will be accepted. It is
	// expected that some other means of authorization is used in this case.
	AcceptVoucher func(context.Context, Voucher) (accept bool, err error)

	// NegotiateTTL is an optional function to select a validity period for a
	// rendezvous blob based on the requested number of seconds and the
	// ownership voucher contents.
	//
	// If NegotiateTTL is not set, the requested TTL will be used.
	NegotiateTTL func(requestedSeconds uint32, ov Voucher) (waitSeconds uint32)
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

// TO2Server implements the TO2 protocol.
type TO2Server struct {
	Session   TO2SessionState
	Vouchers  OwnerVoucherPersistentState
	OwnerKeys OwnerKeyPersistentState

	// Rendezvous directives
	RvInfo func(context.Context, Voucher) ([][]protocol.RvInstruction, error)

	// Create an iterator of service info modules for a given device
	OwnerModules func(ctx context.Context, replacementGUID protocol.GUID, info string, chain []*x509.Certificate, devmod serviceinfo.Devmod, modules []string) iter.Seq2[string, serviceinfo.OwnerModule]

	// VerifyVoucher, if not nil, will be called before creating and responding
	// with a TO2.ProveOVHdr message. Any error will cause TO2 to fail with a
	// not found status code.
	//
	// If VerifyVoucher is nil, the default behavior is to reject all vouchers
	// with zero extensions.
	VerifyVoucher func(context.Context, Voucher) error

	// Server affinity state
	nextModule func() (string, serviceinfo.OwnerModule, bool)
	stop       func()
	plugins    map[string]plugin.Module

	// Optional configuration
	MaxDeviceServiceInfoSize uint16
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
	ownerKey, _, err := s.OwnerKeys.OwnerKey(ownerPubKey.Type)
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
func (s *TO2Server) Respond(ctx context.Context, msgType uint8, msg io.Reader) (respType uint8, resp any) { //nolint:gocyclo
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
	case protocol.TO2DoneMsgType:
		respType = protocol.TO2Done2MsgType
		resp, err = s.to2Done2(ctx, msg)
	}

	// Stop any running plugins if TO2 ended (possibly by error)
	if (msgType == protocol.TO2DeviceServiceInfoMsgType && err != nil) || msgType == protocol.TO2DoneMsgType {
		// Close owner module iterator
		s.stop()

		// Start goroutines to gracefully/forcefully stop plugins. Stopping is
		// given an absolute timeout not tied to the expiration of the request
		// context.
		pluginStopCtx, _ := context.WithTimeout(context.Background(), 5*time.Second) //nolint:govet
		for name, p := range s.plugins {
			pluginGracefulStopCtx, done := context.WithCancel(pluginStopCtx)

			// Allow Graceful stop up to the original shared timeout
			go func(p plugin.Module) {
				defer done()
				if err := p.GracefulStop(pluginGracefulStopCtx); err != nil && !errors.Is(err, context.Canceled) { //nolint:revive,staticcheck
					slog.Warn("graceful stop failed", "module", name, "error", err)
				}
			}(p)

			// Force stop after the shared timeout expires or graceful stop
			// completes
			go func(p plugin.Module) {
				<-pluginGracefulStopCtx.Done()
				_ = p.Stop()
				// TODO: Track state for whether plugins are still stopping
			}(p)
		}
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
