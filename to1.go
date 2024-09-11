// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

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
	var addr string
	if a.DNSAddress != nil {
		addr = *a.DNSAddress
	} else if a.IPAddress != nil {
		addr = a.IPAddress.String()
	}
	if a.Port > 0 {
		port := strconv.Itoa(int(a.Port))
		addr = net.JoinHostPort(addr, port)
	}
	return fmt.Sprintf("%s://%s", a.TransportProtocol, addr)
}

type helloRV struct {
	GUID     GUID
	ASigInfo sigInfo
}

// HelloRV(30) -> HelloRVAck(31)
func (c *Client) helloRv(ctx context.Context, baseURL string) (Nonce, error) {
	eASigInfo, err := sigInfoFor(c.Key, c.PSS)
	if err != nil {
		return Nonce{}, fmt.Errorf("error determining eASigInfo for TO1.HelloRV: %w", err)
	}

	// Define request structure
	msg := helloRV{
		GUID:     c.Cred.GUID,
		ASigInfo: *eASigInfo,
	}

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
func (s *TO1Server) helloRVAck(ctx context.Context, msg io.Reader) (*rvAck, error) {
	var hello helloRV
	if err := cbor.NewDecoder(msg).Decode(&hello); err != nil {
		return nil, fmt.Errorf("error decoding TO1.HelloRV request: %w", err)
	}

	// Check if device has been registered
	if _, _, err := s.RVBlobs.RVBlob(ctx, hello.GUID); errors.Is(err, ErrNotFound) {
		captureErr(ctx, resourceNotFound, "")
		return nil, ErrNotFound
	} else if err != nil {
		return nil, fmt.Errorf("error looking up device: %w", err)
	}

	// Generate and store nonce
	var nonce Nonce
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("error generating nonce for TO1 proof: %w", err)
	}
	if err := s.Session.SetTO1ProofNonce(ctx, nonce); err != nil {
		return nil, fmt.Errorf("error storing nonce for TO1.ProveToRV: %w", err)
	}

	return &rvAck{
		NonceTO1Proof: nonce,
		BSigInfo:      hello.ASigInfo,
	}, nil
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
func (s *TO1Server) rvRedirect(ctx context.Context, msg io.Reader) (*cose.Sign1Tag[To1d, []byte], error) {
	// Decode a fully-parsed and raw COSE Sign1. The latter is used for
	// verifying in a more lenient way, as it doesn't require deterministic
	// encoding of CBOR (even though FDO requires this).
	var token cose.Sign1Tag[cbor.RawBytes, []byte]
	if err := cbor.NewDecoder(msg).Decode(&token); err != nil {
		return nil, fmt.Errorf("error decoding TO1.ProveToRV request: %w", err)
	}
	var eat eatoken
	if err := cbor.Unmarshal([]byte(token.Payload.Val), &eat); err != nil {
		return nil, fmt.Errorf("error decoding TO1.ProveToRV request: %w", err)
	}

	// Check EAT nonce
	proofNonce, err := s.Session.TO1ProofNonce(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting TO1 proof nonce: %w", err)
	}
	nonce, ok := eat[eatNonceClaim].([]byte)
	if !ok {
		captureErr(ctx, invalidMessageErrCode, "")
		return nil, fmt.Errorf("EAT missing nonce claim")
	}
	if !bytes.Equal(nonce, proofNonce[:]) {
		captureErr(ctx, invalidMessageErrCode, "")
		return nil, fmt.Errorf("EAT nonce does not match")
	}

	// Get GUID from EAT
	ueid, ok := eat[eatUeidClaim].([]byte)
	if !ok {
		captureErr(ctx, invalidMessageErrCode, "")
		return nil, fmt.Errorf("EAT missing UEID claim")
	}
	if len(ueid) != 1+len(GUID{}) {
		captureErr(ctx, invalidMessageErrCode, "")
		return nil, fmt.Errorf("EAT UEID claim is not a valid length")
	}
	if ueid[0] != eatRandUeid {
		captureErr(ctx, invalidMessageErrCode, "")
		return nil, fmt.Errorf("EAT UEID type must be RAND")
	}
	var guid GUID
	_ = copy(guid[:], ueid[1:])

	// Get device public key from ownership voucher
	blob, ov, err := s.RVBlobs.RVBlob(ctx, guid)
	if err != nil {
		return nil, fmt.Errorf("error looking up rendezvous blob: %w", err)
	}
	pub, err := ov.DevicePublicKey()
	if err != nil {
		return nil, fmt.Errorf("error getting device public key from ownership voucher: %w", err)
	}

	// Verify EAT signature
	if ok, err := token.Verify(pub, nil, nil); err != nil {
		captureErr(ctx, invalidMessageErrCode, "")
		return nil, fmt.Errorf("error verifying EAT signature: %w", err)
	} else if !ok {
		captureErr(ctx, invalidMessageErrCode, "")
		return nil, fmt.Errorf("%w: EAT signature verification failed", ErrCryptoVerifyFailed)
	}

	// Return RV blob
	return blob.Tag(), nil
}
