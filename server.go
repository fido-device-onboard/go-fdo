// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"io"
	"iter"
	"time"

	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/plugin"
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
	DeviceInfo func(context.Context, *T, []*x509.Certificate) (string, KeyType, KeyEncoding, error)

	// When set, new vouchers will be extended using the appropriate owner key.
	AutoExtend interface {
		ManufacturerKey(keyType KeyType) (crypto.Signer, []*x509.Certificate, error)
		OwnerKey(keyType KeyType) (crypto.Signer, []*x509.Certificate, error)
	}

	// When set, new vouchers will be registered for rendezvous.
	AutoTO0 interface {
		OwnerKey(keyType KeyType) (crypto.Signer, []*x509.Certificate, error)
		SetRVBlob(context.Context, *Voucher, *cose.Sign1[To1d, []byte], time.Time) error
	}
	AutoTO0Addrs []RvTO2Addr

	// Rendezvous directives
	RvInfo func(context.Context, *Voucher) ([][]RvInstruction, error)
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
	case diAppStartMsgType:
		respType = diSetCredentialsMsgType
		resp, err = s.setCredentials(ctx, msg)
	case diSetHmacMsgType:
		respType = diDoneMsgType
		resp, err = s.diDone(ctx, msg)
	}
	if err == nil {
		return respType, resp
	}

	// Default to error code 500, error message of err parameter, and timestamp
	// of the current time
	errMsg := errMsgFromContext(ctx)
	if errMsg.Code == 0 {
		errMsg.Code = internalServerErrCode
	}
	if errMsg.ErrString == "" {
		errMsg.ErrString = err.Error()
	}
	if errMsg.Timestamp == 0 {
		errMsg.Timestamp = time.Now().Unix()
	}
	return ErrorMsgType, errMsg
}

// TO0Server implements the TO0 protocol.
type TO0Server struct {
	Session TO0SessionState
	RVBlobs RendezvousBlobPersistentState
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
	case to0HelloMsgType:
		respType = to0HelloAckMsgType
		resp, err = s.helloAck(ctx, msg)
	case to0OwnerSignMsgType:
		respType = to0AcceptOwnerMsgType
		resp, err = s.acceptOwner(ctx, msg)
	}
	if err == nil {
		return respType, resp
	}

	// Default to error code 500, error message of err parameter, and timestamp
	// of the current time
	errMsg := errMsgFromContext(ctx)
	if errMsg.Code == 0 {
		errMsg.Code = internalServerErrCode
	}
	if errMsg.ErrString == "" {
		errMsg.ErrString = err.Error()
	}
	if errMsg.Timestamp == 0 {
		errMsg.Timestamp = time.Now().Unix()
	}
	return ErrorMsgType, errMsg
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
	case to1HelloRVMsgType:
		respType = to1HelloRVAckMsgType
		resp, err = s.helloRVAck(ctx, msg)
	case to1ProveToRVMsgType:
		respType = to1RVRedirectMsgType
		resp, err = s.rvRedirect(ctx, msg)
	}
	if err == nil {
		return respType, resp
	}

	// Default to error code 500, error message of err parameter, and timestamp
	// of the current time
	errMsg := errMsgFromContext(ctx)
	if errMsg.Code == 0 {
		errMsg.Code = internalServerErrCode
	}
	if errMsg.ErrString == "" {
		errMsg.ErrString = err.Error()
	}
	if errMsg.Timestamp == 0 {
		errMsg.Timestamp = time.Now().Unix()
	}
	return ErrorMsgType, errMsg
}

// TO2Server implements the TO2 protocol.
type TO2Server struct {
	Session   TO2SessionState
	Vouchers  OwnerVoucherPersistentState
	OwnerKeys OwnerKeyPersistentState

	// Rendezvous directives
	RvInfo func(context.Context, *Voucher) ([][]RvInstruction, error)

	// Create an iterator of service info modules for a given device
	OwnerModules func(ctx context.Context, replacementGUID GUID, info string, chain []*x509.Certificate, devmod Devmod, modules []string) iter.Seq2[string, serviceinfo.OwnerModule]

	// Server affinity state
	nextModule func() (string, serviceinfo.OwnerModule, bool)
	stop       func()
	plugins    []plugin.Module

	// Optional configuration
	MaxDeviceServiceInfoSize uint16
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
	case to2HelloDeviceMsgType:
		respType = to2ProveOVHdrMsgType
		resp, err = s.proveOVHdr(ctx, msg)
	case to2GetOVNextEntryMsgType:
		respType = to2OVNextEntryMsgType
		resp, err = s.ovNextEntry(ctx, msg)
	case to2ProveDeviceMsgType:
		respType = to2SetupDeviceMsgType
		resp, err = s.setupDevice(ctx, msg)
	case to2DeviceServiceInfoReadyMsgType:
		respType = to2OwnerServiceInfoReadyMsgType
		resp, err = s.ownerServiceInfoReady(ctx, msg)
	case to2DeviceServiceInfoMsgType:
		respType = to2OwnerServiceInfoMsgType
		resp, err = s.ownerServiceInfo(ctx, msg)
	case to2DoneMsgType:
		respType = to2Done2MsgType
		resp, err = s.to2Done2(ctx, msg)
	}

	// Stop any running plugins if TO2 ended (possibly by error)
	if (msgType == to2DeviceServiceInfoMsgType && err != nil) || msgType == to2DoneMsgType {
		// Close owner module iterator
		s.stop()

		// Start goroutines to gracefully/forcefully stop plugins. Stopping is
		// given an absolute timeout not tied to the expiration of the request
		// context.
		//
		// TODO: Make timeout configurable?
		pluginStopCtx, _ := context.WithTimeout(context.Background(), 5*time.Second) //nolint:govet
		for _, p := range s.plugins {
			pluginGracefulStopCtx, done := context.WithCancel(pluginStopCtx)

			// Allow Graceful stop up to the original shared timeout
			go func(p plugin.Module) {
				defer done()
				if err := p.GracefulStop(pluginGracefulStopCtx); err != nil && !errors.Is(err, context.Canceled) { //nolint:revive,staticcheck
					// TODO: Write to error log
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
		errMsg.Code = internalServerErrCode
	}
	if errMsg.ErrString == "" {
		errMsg.ErrString = err.Error()
	}
	if errMsg.Timestamp == 0 {
		errMsg.Timestamp = time.Now().Unix()
	}
	return ErrorMsgType, errMsg
}
