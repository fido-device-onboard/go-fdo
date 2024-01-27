// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"crypto"
	"fmt"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
)

// TO1 Message Types
const (
	to1HelloRVMsgType    uint8 = 30
	to1HelloRVAckMsgType uint8 = 31
	to1ProveToRVMsgType  uint8 = 32
	to1RVRedirectMsgType uint8 = 33
)

// RvTO2Addr indicates to the device how to connect to the owner service.
type RvTO2Addr struct {
	IPAddress         []byte
	DNSAddress        string
	Port              uint16
	TransportProtocol TransportProtocol
}

// HelloRV(30) -> HelloRVAck(31)
func (c *Client) helloRv(ctx context.Context, baseURL string) (Nonce, error) {
	eASigInfo, err := sigInfoFor(c.Key, c.PSS)
	if err != nil {
		return Nonce{}, fmt.Errorf("error determining eASigInfo for TO1.HelloRV: %w", err)
	}

	// Define request structure
	var msg struct {
		GUID     GUID
		ASigInfo sigInfo
	}
	msg.GUID = c.Cred.GUID
	msg.ASigInfo = *eASigInfo

	// Make request
	typ, resp, err := c.Transport.Send(ctx, baseURL, to1HelloRVMsgType, msg)
	if err != nil {
		return Nonce{}, fmt.Errorf("error sending TO1.HelloRV: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	switch typ {
	case to1HelloRVAckMsgType:
		captureMsgType(ctx, typ)
		var ack struct {
			NonceTO1Proof Nonce
			BSigInfo      sigInfo
		}
		if err := cbor.NewDecoder(resp).Decode(&ack); err != nil {
			captureErr(ctx, messageBodyErrCode, "")
			return Nonce{}, fmt.Errorf("error parsing TO1.HelloRVAck contents: %w", err)
		}
		return ack.NonceTO1Proof, nil

	case errorMsgType:
		var errMsg ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return Nonce{}, fmt.Errorf("error parsing error message contents of TO1.HelloRV response: %w", err)
		}
		return Nonce{}, fmt.Errorf("error received from TO1.HelloRV request: %w", errMsg)

	default:
		captureErr(ctx, messageBodyErrCode, "")
		return Nonce{}, fmt.Errorf("unexpected message type for response to TO1.HelloRV: %d", typ)
	}
}

// ProveToRV(32) -> RVRedirect(33)
func (c *Client) proveToRv(ctx context.Context, baseURL string, nonce Nonce) ([]RvTO2Addr, error) {
	// Define request structure
	token := cose.Sign1[eatoken]{
		Header:  cose.Header{},
		Payload: cbor.NewBstrPtr(newEAT(c.Cred.GUID, nonce, nil, nil)),
	}
	opts, err := signOptsFor(c.Key, c.PSS)
	if err != nil {
		return nil, fmt.Errorf("error determining signing options for TO1.ProveToRV: %w", err)
	}
	if err := token.Sign(c.Key, nil, opts); err != nil {
		return nil, fmt.Errorf("error signing EAT payload for TO1.ProveToRV: %w", err)
	}
	msg := token.Tag()

	// Make request
	typ, resp, err := c.Transport.Send(ctx, baseURL, to1ProveToRVMsgType, msg)
	if err != nil {
		return nil, fmt.Errorf("error sending TO1.ProveToRV: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	switch typ {
	case to1RVRedirectMsgType:
		captureMsgType(ctx, typ)
		var redirect struct {
			To1dRV       []RvTO2Addr
			To1dTo0dHash Hash
		}
		if err := cbor.NewDecoder(resp).Decode(&redirect); err != nil {
			captureErr(ctx, messageBodyErrCode, "")
			return nil, fmt.Errorf("error parsing TO1.RVRedirect contents: %w", err)
		}
		return redirect.To1dRV, nil

	case errorMsgType:
		var errMsg ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return nil, fmt.Errorf("error parsing error message contents of TO1.ProveToRV response: %w", err)
		}
		return nil, fmt.Errorf("error received from TO1.ProveToRV request: %w", errMsg)

	default:
		captureErr(ctx, messageBodyErrCode, "")
		return nil, fmt.Errorf("unexpected message type for response to TO1.ProveToRV: %d", typ)
	}
}

func sigInfoFor(key crypto.Signer, usePSS bool) (*sigInfo, error) {
	opts, err := signOptsFor(key, usePSS)
	if err != nil {
		return nil, err
	}
	algID, err := cose.SignatureAlgorithmFor(key, opts)
	if err != nil {
		return nil, err
	}
	return &sigInfo{Type: algID}, nil
}
