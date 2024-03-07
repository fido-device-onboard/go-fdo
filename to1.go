// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"

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
	IPAddress         *net.IP // Can be null, unless DNSAddress is null
	DNSAddress        *string // Can be null, unless IPAddress is null
	Port              uint16
	TransportProtocol TransportProtocol
}

func (a RvTO2Addr) String() string {
	var addr any
	if a.DNSAddress != nil {
		addr = *a.DNSAddress
	} else if a.IPAddress != nil {
		addr = *a.IPAddress
	}
	if a.Port == 0 {
		return fmt.Sprintf("%s://%s", a.TransportProtocol, addr)
	}
	return fmt.Sprintf("%s://%s:%d", a.TransportProtocol, addr, a.Port)
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
	typ, resp, err := c.Transport.Send(ctx, baseURL, to1HelloRVMsgType, msg, nil)
	if err != nil {
		return Nonce{}, fmt.Errorf("error sending TO1.HelloRV: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	switch typ {
	case to1HelloRVAckMsgType:
		captureMsgType(ctx, typ)
		var ack rvAck
		if err := cbor.NewDecoder(resp).Decode(&ack); err != nil {
			captureErr(ctx, messageBodyErrCode, "")
			return Nonce{}, fmt.Errorf("error parsing TO1.HelloRVAck contents: %w", err)
		}
		return ack.NonceTO1Proof, nil

	case ErrorMsgType:
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

type rvAck struct {
	NonceTO1Proof Nonce
	BSigInfo      sigInfo
}

// HelloRV(30) -> HelloRVAck(31)
func (s *Server) helloRVAck(ctx context.Context, msg io.Reader) (rvAck, error) {
	panic("unimplemented")
}

// To1d is a "blob" that indicates a network address (RVTO2Addr) where the
// Device can find a prospective Owner for the TO2 Protocol.
type To1d struct {
	RV       []RvTO2Addr
	To0dHash Hash
}

func (to1d To1d) String() string {
	s := "to1d[\n"
	s += "  RV:\n"
	for _, addr := range to1d.RV {
		s += "    - " + addr.String() + "\n"
	}
	s += "  To0dHash:\n"
	s += "    Algorithm: " + to1d.To0dHash.Algorithm.String() + "\n"
	s += "    Value: " + hex.EncodeToString(to1d.To0dHash.Value) + "\n"
	return s + "]"
}

// ProveToRV(32) -> RVRedirect(33)
func (c *Client) proveToRv(ctx context.Context, baseURL string, nonce Nonce) (*cose.Sign1[To1d, []byte], error) {
	// Define request structure
	token := cose.Sign1[eatoken, []byte]{
		Payload: cbor.NewByteWrap(newEAT(c.Cred.GUID, nonce, nil, nil)),
	}
	opts, err := signOptsFor(c.Key, c.PSS)
	if err != nil {
		return nil, fmt.Errorf("error determining signing options for TO1.ProveToRV: %w", err)
	}
	if err := token.Sign(c.Key, nil, nil, opts); err != nil {
		return nil, fmt.Errorf("error signing EAT payload for TO1.ProveToRV: %w", err)
	}
	msg := token.Tag()

	// Make request
	typ, resp, err := c.Transport.Send(ctx, baseURL, to1ProveToRVMsgType, msg, nil)
	if err != nil {
		return nil, fmt.Errorf("error sending TO1.ProveToRV: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	switch typ {
	case to1RVRedirectMsgType:
		captureMsgType(ctx, typ)
		var redirect cose.Sign1Tag[To1d, []byte]
		if err := cbor.NewDecoder(resp).Decode(&redirect); err != nil {
			captureErr(ctx, messageBodyErrCode, "")
			return nil, fmt.Errorf("error parsing TO1.RVRedirect contents: %w", err)
		}
		return redirect.Untag(), nil

	case ErrorMsgType:
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

// ProveToRV(32) -> RVRedirect(33)
func (s *Server) rvRedirect(ctx context.Context, msg io.Reader) (cose.Sign1Tag[To1d, []byte], error) {
	panic("unimplemented")
}
