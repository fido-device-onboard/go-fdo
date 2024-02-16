// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"crypto"
	"crypto/x509"
	"io"
	"time"
)

// Server implements business logic handling for all FDO protocols.
type Server struct {
	// Service to manage generating and decoding tokens
	Tokens TokenService

	// Correlates a device certificate chain to info provided in the
	// DI.AppStart message
	DeviceForInfo func(info DeviceMfgInfo) ([]*x509.Certificate, error)

	// Rendezvous directives
	RvInfo [][]RvInstruction

	// ManufacturerKeys used for device initialization
	ManufacturerKeys func(KeyType) (crypto.Signer, PublicKey, bool)
}

// Respond validates a request and returns the appropriate response message.
//
//nolint:gocyclo, Message dispatch
func (s *Server) Respond(ctx context.Context, token string, msgType uint8, msg io.Reader) (newToken string, respType uint8, resp any) {
	ctx = contextWithErrMsg(ctx)
	captureMsgType(ctx, msgType)

	// Generate a new token if none set
	if token == "" {
		var err error
		token, err = s.Tokens.NewSession(ctx)
		if err != nil {
			return newToken, ErrorMsgType, ErrorMessage{
				PrevMsgType:   msgType,
				Code:          internalServerErrCode,
				ErrString:     err.Error(),
				Timestamp:     time.Now().Unix(),
				CorrelationID: nil, // TODO: From token?
			}
		}
	}

	// Handle each message type
	var err error
	switch msgType {
	// DI
	case diAppStartMsgType:
		respType = diSetCredentialsMsgType
		resp, err = s.setCredentials(ctx, token, msg)
	case diSetHmacMsgType:
		respType = diDoneMsgType
		resp, err = s.diDone(ctx, token, msg)

	// TO1
	case to1HelloRVMsgType:
		respType = to1HelloRVAckMsgType
		resp, err = s.helloRVAck(ctx, token, msg)
	case to1ProveToRVMsgType:
		respType = to1RVRedirectMsgType
		resp, err = s.rvRedirect(ctx, token, msg)

	// TO2
	case to2HelloDeviceMsgType:
		respType = to2ProveOVHdrMsgType
		resp, err = s.proveOVHdr(ctx, token, msg)
	case to2GetOVNextEntryMsgType:
		respType = to2OVNextEntryMsgType
		resp, err = s.ovNextEntry(ctx, token, msg)
	case to2ProveDeviceMsgType:
		respType = to2SetupDeviceMsgType
		resp, err = s.setupDevice(ctx, token, msg)
	case to2DeviceServiceInfoReadyMsgType:
		respType = to2OwnerServiceInfoReadyMsgType
		resp, err = s.ownerServiceInfoReady(ctx, token, msg)
	case to2DeviceServiceInfoMsgType:
		respType = to2OwnerServiceInfoMsgType
		resp, err = s.ownerServiceInfo(ctx, token, msg)
	case to2DoneMsgType:
		respType = to2Done2MsgType
		resp, err = s.to2Done2(ctx, token, msg)
	}
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
