// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"io"
	"time"
)

// Server implements business logic handling for all FDO protocols.
type Server struct {
	// Protocol session state
	State       TokenService
	NewDevices  VoucherCreationState
	Proofs      VoucherProofState
	KeyExchange KeyExchangeState
	Nonces      NonceState

	// Persistent state
	Devices   VoucherPersistentState
	OwnerKeys OwnerKeyPersistentState

	// Rendezvous directives
	RvInfo [][]RvInstruction
}

// Respond validates a request and returns the appropriate response message.
//
//nolint:gocyclo, Message dispatch
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
		token, err = s.State.NewToken(ctx, DIProtocol)
	case to1HelloRVMsgType:
		token, err = s.State.NewToken(ctx, TO1Protocol)
	case to2HelloDeviceMsgType:
		token, err = s.State.NewToken(ctx, TO2Protocol)
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
	ctx = s.State.TokenContext(ctx, token)

	// Handle each message type
	switch msgType {
	// DI
	case diAppStartMsgType:
		respType = diSetCredentialsMsgType
		resp, err = s.setCredentials(ctx, msg)
	case diSetHmacMsgType:
		respType = diDoneMsgType
		resp, err = s.diDone(ctx, msg)

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
	newToken, _ = s.State.TokenFromContext(ctx)
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
	return newToken, ErrorMsgType, errMsg
}
