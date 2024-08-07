// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"iter"
	"os"
	"time"

	"github.com/fido-device-onboard/go-fdo/plugin"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// Server implements business logic handling for all FDO protocols.
type Server struct {
	// Protocol session state
	Tokens TokenService
	DI     DISessionState
	TO0    TO0SessionState
	TO1    TO1SessionState
	TO2    TO2SessionState

	// Persistent state
	RVBlobs   RendezvousBlobPersistentState
	Vouchers  VoucherPersistentState
	OwnerKeys OwnerKeyPersistentState

	// Rendezvous directives
	RvInfo [][]RvInstruction

	// Create an iterator of service info modules for a given device
	OwnerModules func(ctx context.Context, replacementGUID GUID, info string, chain []*x509.Certificate, devmod Devmod, modules []string) iter.Seq[serviceinfo.OwnerModule]

	// Server affinity state
	nextModule func() (serviceinfo.OwnerModule, bool)
	stop       func()
	plugins    []plugin.Module

	// Optional configuration
	MaxDeviceServiceInfoSize uint16
}

// Respond validates a request and returns the appropriate response message.
//
//nolint:gocyclo // Message dispatch
func (s *Server) Respond(ctx context.Context, token string, msgType uint8, msg io.Reader) (newToken string, respType uint8, resp any) {
	// Inject a mutable error into the context for error info capturing without
	// complex error wrapping or overburdened method signatures.
	ctx = contextWithErrMsg(ctx)
	captureMsgType(ctx, msgType)

	// Inject token state into context to keep method signatures clean while
	// allowing some implementations to mutate tokens on every message.
	var err error
	switch msgType {
	case diAppStartMsgType:
		token, err = s.Tokens.NewToken(ctx, DIProtocol)
	case to0HelloMsgType:
		token, err = s.Tokens.NewToken(ctx, TO0Protocol)
	case to1HelloRVMsgType:
		token, err = s.Tokens.NewToken(ctx, TO1Protocol)
	case to2HelloDeviceMsgType:
		token, err = s.Tokens.NewToken(ctx, TO2Protocol)
	}
	if err != nil {
		return "", ErrorMsgType, ErrorMessage{
			Code:          internalServerErrCode,
			PrevMsgType:   msgType,
			ErrString:     err.Error(),
			Timestamp:     time.Now().Unix(),
			CorrelationID: nil,
		}
	}
	ctx = s.Tokens.TokenContext(ctx, token)

	// Handle each message type
	switch msgType {
	// DI
	case diAppStartMsgType:
		respType = diSetCredentialsMsgType
		resp, err = s.setCredentials(ctx, msg)
	case diSetHmacMsgType:
		respType = diDoneMsgType
		resp, err = s.diDone(ctx, msg)

	// TO0
	case to0HelloMsgType:
		respType = to0HelloAckMsgType
		resp, err = s.helloAck(ctx, msg)
	case to0OwnerSignMsgType:
		respType = to0AcceptOwnerMsgType
		resp, err = s.acceptOwner(ctx, msg)

	// TO1
	case to1HelloRVMsgType:
		respType = to1HelloRVAckMsgType
		resp, err = s.helloRVAck(ctx, msg)
	case to1ProveToRVMsgType:
		respType = to1RVRedirectMsgType
		resp, err = s.rvRedirect(ctx, msg)

	// TO2
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
	if (msgType == to2DeviceServiceInfoMsgType && err != nil) || msgType == to2Done2MsgType {
		// Close owner module iterator
		s.stop()

		// Start goroutines to gracefully/forcefully stop plugins. Stopping is
		// given an absolute timeout not tied to the expiration of the request
		// context.
		//
		// TODO: Make timeout configurable?
		pluginStopCtx, _ := context.WithTimeout(context.Background(), 5*time.Second)
		for _, p := range s.plugins {
			pluginGracefulStopCtx, done := context.WithCancel(pluginStopCtx)

			// Allow Graceful stop up to the original shared timeout
			go func() {
				defer done()
				if err := p.GracefulStop(pluginStopCtx); err != nil && !errors.Is(err, context.Canceled) {
					// TODO: Write to error log
				}
			}()

			// Force stop after the shared timeout expires or graceful stop
			// completes
			go func() {
				<-pluginGracefulStopCtx.Done()
				_ = p.Stop()
			}()
		}
	}

	// Return response with possibly altered token
	newToken, _ = s.Tokens.TokenFromContext(ctx)
	if err == nil {
		return newToken, respType, resp
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
	if err := s.Tokens.InvalidateToken(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "[WARNING] error invalidating token: %v\n", err)
	}
	return "", ErrorMsgType, errMsg
}
