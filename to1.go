// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"

	"github.com/fido-device-onboard/go-fdo/cose"
)

// TO1 Message Types
const (
	TO1HelloRVMsgType    uint8 = 30
	TO1HelloRVAckMsgType uint8 = 31
	TO1ProveToRVMsgType  uint8 = 32
	TO1RVRedirectMsgType uint8 = 33
)

// RvTO2Addr indicates to the device how to connect to the owner service.
type RvTO2Addr struct {
	IPAddress         []byte
	DNSAddress        string
	Port              uint16
	TransportProtocol TransportProtocol
}

// HelloRV(30) -> HelloRVAck(31)
func (c *Client) helloRv(ctx context.Context, guid GUID, sig *SigInfo) (*Nonce, *SigInfo, error) {
	type HelloRv struct {
		GUID     GUID
		ASigInfo *SigInfo
	}

	type HelloRvAck struct {
		NonceTO1Proof []byte
		ASigInfo      *SigInfo
	}

	panic("unimplemented")
}

// ProveToRV(32) -> RVRedirect(33)
func (c *Client) proveToRv(ctx context.Context, token cose.Sign1[EAToken]) ([]RvTO2Addr, error) {
	type RvRedirect struct {
		To1dRV       []RvTO2Addr
		To1dTo0dHash Hash
	}

	panic("unimplemented")
}
