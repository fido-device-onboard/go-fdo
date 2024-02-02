// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/kex"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// TO2 Message Types
const (
	to2HelloDeviceMsgType            uint8 = 60
	to2ProveOVHdrMsgType             uint8 = 61
	to2GetOVNextEntryMsgType         uint8 = 62
	to2OVNextEntryMsgType            uint8 = 63
	to2ProveDeviceMsgType            uint8 = 64
	to2SetupDeviceMsgType            uint8 = 65
	to2DeviceServiceInfoReadyMsgType uint8 = 66
	to2OwnerServiceInfoReadyMsgType  uint8 = 67
	to2DeviceServiceInfoMsgType      uint8 = 68
	to2OwnerServiceInfoMsgType       uint8 = 69
	to2DoneMsgType                   uint8 = 70
	to2Done2MsgType                  uint8 = 71
)

// COSE claims for TO2ProveOVHdrUnprotectedHeaders
var (
	to2NonceClaim       = cose.Label{Int64: 256}
	to2OwnerPubKeyClaim = cose.Label{Int64: 257}
)

type ovhValidationContext struct {
	OVH                 VoucherHeader
	OVHHmac             Hmac
	NumVoucherEntries   int
	PublicKeyToValidate crypto.PublicKey
}

// Verify owner by sending HelloDevice and validating the response, as well as
// all ownership voucher entries, which are retrieved iteratively with
// subsequence requests.
func (c *Client) verifyOwner(ctx context.Context, baseURL string) (Nonce, *VoucherHeader, kex.Session, error) {
	// Construct ownership voucher from parts received from the owner service
	proveDeviceNonce, info, session, err := c.helloDevice(ctx, baseURL)
	if err != nil {
		return Nonce{}, nil, nil, err
	}
	if info.NumVoucherEntries == 0 {
		return Nonce{}, nil, nil, fmt.Errorf("ownership voucher cannot have zero entries")
	}
	var entries []cose.Sign1Tag[VoucherEntryPayload]
	for i := 0; i < info.NumVoucherEntries; i++ {
		entry, err := c.nextOVEntry(ctx, baseURL, i)
		if err != nil {
			return Nonce{}, nil, nil, err
		}
		entries = append(entries, *entry)
	}
	ov := Voucher{
		Header:  *cbor.NewBstr(info.OVH),
		Hmac:    info.OVHHmac,
		Entries: entries,
	}

	// Verify ownership voucher header
	if err := ov.VerifyHeader(c.Hmac); err != nil {
		captureErr(ctx, invalidMessageErrCode, "")
		return Nonce{}, nil, nil, fmt.Errorf("bad ownership voucher header from TO2.ProveOVHdr: %w", err)
	}

	// Verify that the owner service corresponds to the most recent device
	// initialization performed by checking that the voucher header has a GUID
	// and/or manufacturer key corresponding to the stored device credentials.
	if err := ov.VerifyManufacturerKey(c.Cred.PublicKeyHash); err != nil {
		captureErr(ctx, invalidMessageErrCode, "")
		return Nonce{}, nil, nil, fmt.Errorf("bad ownership voucher header from TO2.ProveOVHdr: %w", err)
	}

	// Verify each entry in the voucher's list by performing iterative
	// signature and hash (header and GUID/devInfo) checks.
	if err := ov.VerifyEntries(); err != nil {
		captureErr(ctx, invalidMessageErrCode, "")
		return Nonce{}, nil, nil, fmt.Errorf("bad ownership voucher entries from TO2.ProveOVHdr: %w", err)
	}

	// Ensure that the voucher entry chain ends with given owner key.
	//
	// Note that this check is REQUIRED in this case, because the the owner public
	// key from the ProveOVHdr message's unprotected headers is used to
	// validate its COSE signature. If the public key were not to match the
	// last entry of the voucher, then it would not be known that ProveOVHdr
	// was signed by the intended owner service.
	expectedOwnerPub, err := ov.Entries[len(ov.Entries)-1].Payload.Val.PublicKey.Public()
	if err != nil {
		return Nonce{}, nil, nil, fmt.Errorf("error parsing last public key of ownership voucher: %w", err)
	}
	if !info.PublicKeyToValidate.(interface{ Equal(crypto.PublicKey) bool }).Equal(expectedOwnerPub) {
		captureErr(ctx, invalidMessageErrCode, "")
		return Nonce{}, nil, nil, fmt.Errorf("owner public key did not match last entry in ownership voucher")
	}

	return proveDeviceNonce, &info.OVH, session, nil
}

// HelloDevice(60) -> ProveOVHdr(61)
//
//nolint:gocyclo, This is very complex validation that is better understood linearly
func (c *Client) helloDevice(ctx context.Context, baseURL string) (Nonce, *ovhValidationContext, kex.Session, error) {
	// Generate a new nonce
	var proveOVNonce Nonce
	if _, err := rand.Read(proveOVNonce[:]); err != nil {
		return Nonce{}, nil, nil, fmt.Errorf("error generating new nonce for TO2.HelloDevice request: %w", err)
	}

	// Select SigInfo using SHA384 when available
	aSigInfo, err := sigInfoFor(c.Key, c.PSS)
	if err != nil {
		return Nonce{}, nil, nil, fmt.Errorf("error select aSigInfo for TO2.HelloDevice request: %w", err)
	}

	// Create a request structure
	helloDeviceMsg := struct {
		MaxDeviceMessageSize uint16
		GUID                 GUID
		NonceTO2ProveOV      Nonce
		KexSuiteName         kex.Suite
		CipherSuite          kex.CipherSuiteID
		SigInfoA             sigInfo
	}{
		MaxDeviceMessageSize: c.MaxServiceInfoSizeReceive, // TODO: Should this be separately configurable?
		GUID:                 c.Cred.GUID,
		NonceTO2ProveOV:      proveOVNonce,
		KexSuiteName:         c.KeyExchange,
		CipherSuite:          c.CipherSuite,
		SigInfoA:             *aSigInfo,
	}

	// Make a request
	typ, resp, err := c.Transport.Send(ctx, baseURL, to2HelloDeviceMsgType, helloDeviceMsg, nil)
	if err != nil {
		return Nonce{}, nil, nil, err
	}
	defer func() { _ = resp.Close() }()

	// Enforce MaxDeviceMessageSize
	resp = struct {
		io.Reader
		io.Closer
	}{
		Reader: io.LimitReader(resp, int64(c.MaxServiceInfoSizeReceive)),
		Closer: resp,
	}

	// Parse response
	var proveOVHdr cose.Sign1Tag[struct {
		OVH                 cbor.Bstr[VoucherHeader]
		NumOVEntries        uint8
		OVHHmac             Hmac
		NonceTO2ProveOV     Nonce
		SigInfoB            sigInfo
		KeyExchangeA        []byte
		HelloDeviceHash     Hash
		MaxOwnerMessageSize uint16
	}]
	switch typ {
	case to2ProveOVHdrMsgType:
		captureMsgType(ctx, typ)
		if err := cbor.NewDecoder(resp).Decode(&proveOVHdr); err != nil {
			captureErr(ctx, messageBodyErrCode, "")
			return Nonce{}, nil, nil, fmt.Errorf("error parsing TO2.ProveOVHdr contents: %w", err)
		}

	case ErrorMsgType:
		var errMsg ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return Nonce{}, nil, nil, fmt.Errorf("error parsing error message contents of TO2.HelloDevice response: %w", err)
		}
		return Nonce{}, nil, nil, fmt.Errorf("error received from TO2.HelloDevice request: %w", errMsg)

	default:
		captureErr(ctx, messageBodyErrCode, "")
		return Nonce{}, nil, nil, fmt.Errorf("unexpected message type for response to TO2.HelloDevice: %d", typ)
	}

	// Validate the HelloDeviceHash
	helloDeviceHash := proveOVHdr.Payload.Val.HelloDeviceHash.Algorithm.HashFunc().New()
	if err := cbor.NewEncoder(helloDeviceHash).Encode(helloDeviceMsg); err != nil {
		return Nonce{}, nil, nil, fmt.Errorf("error hashing HelloDevice message to verify against TO2.ProveOVHdr payload's hash: %w", err)
	}
	if !bytes.Equal(proveOVHdr.Payload.Val.HelloDeviceHash.Value, helloDeviceHash.Sum(nil)) {
		captureErr(ctx, invalidMessageErrCode, "")
		return Nonce{}, nil, nil, fmt.Errorf("hash of HelloDevice message TO2.ProveOVHdr did not match the message sent")
	}

	// Parse owner public key
	var ownerPubKey PublicKey
	if found, err := proveOVHdr.Unprotected.Parse(to2OwnerPubKeyClaim, &ownerPubKey); !found {
		captureErr(ctx, invalidMessageErrCode, "")
		return Nonce{}, nil, nil, fmt.Errorf("owner pubkey unprotected header missing from TO2.ProveOVHdr response message")
	} else if err != nil {
		captureErr(ctx, invalidMessageErrCode, "")
		return Nonce{}, nil, nil, fmt.Errorf("owner pubkey unprotected header from TO2.ProveOVHdr could not be unmarshaled: %w", err)
	}

	// Validate response signature and nonce. While the payload signature
	// verification is performed using the untrusted owner public key from the
	// headers, this is acceptable, because the owner public key will be
	// subsequently verified when the voucher entry chain is built and
	// verified.
	key, err := ownerPubKey.Public()
	if err != nil {
		captureErr(ctx, invalidMessageErrCode, "")
		return Nonce{}, nil, nil, fmt.Errorf("error parsing owner public key to verify TO2.ProveOVHdr payload signature: %w", err)
	}
	if ok, err := proveOVHdr.Verify(key, nil); err != nil {
		captureErr(ctx, invalidMessageErrCode, "")
		return Nonce{}, nil, nil, fmt.Errorf("error verifying TO2.ProveOVHdr payload signature: %w", err)
	} else if !ok {
		captureErr(ctx, invalidMessageErrCode, "")
		return Nonce{}, nil, nil, fmt.Errorf("%w: TO2.ProveOVHdr payload signature verification failed", ErrCryptoVerifyFailed)
	}
	if proveOVHdr.Payload.Val.NonceTO2ProveOV != proveOVNonce {
		captureErr(ctx, invalidMessageErrCode, "")
		return Nonce{}, nil, nil, fmt.Errorf("nonce in TO2.ProveOVHdr did not match nonce sent in TO2.HelloDevice")
	}

	// proveOVHdr.Payload.Val.SigInfoB does not need to be validated. It is
	// just a formality for ECDSA/RSA keys, left over from EPID support.

	// TODO: Track proveOVHdr.Payload.Val.MaxOwnerMessageSize and later
	// calculate MTU=min(MaxOwnerMessageSize, MaxOwnerServiceInfoSize) for
	// better spec compliance, but honestly MaxOwnerMessageSize doesn't make
	// that much sense. What can you do with it that you can't with service
	// info max - fail early if TO2.ProveDevice is necessarily too large to be
	// received?

	// Parse nonce
	var cuphNonce Nonce
	if found, err := proveOVHdr.Unprotected.Parse(to2NonceClaim, &cuphNonce); !found {
		captureErr(ctx, invalidMessageErrCode, "")
		return Nonce{}, nil, nil, fmt.Errorf("nonce unprotected header missing from TO2.ProveOVHdr response message")
	} else if err != nil {
		captureErr(ctx, invalidMessageErrCode, "")
		return Nonce{}, nil, nil, fmt.Errorf("nonce unprotected header from TO2.ProveOVHdr could not be unmarshaled: %w", err)
	}

	return cuphNonce,
		&ovhValidationContext{
			OVH:                 proveOVHdr.Payload.Val.OVH.Val,
			OVHHmac:             proveOVHdr.Payload.Val.OVHHmac,
			NumVoucherEntries:   int(proveOVHdr.Payload.Val.NumOVEntries),
			PublicKeyToValidate: key,
		},
		c.KeyExchange.New(proveOVHdr.Payload.Val.KeyExchangeA, c.CipherSuite),
		nil

}

// GetOVNextEntry(62) -> OVNextEntry(63)
func (c *Client) nextOVEntry(ctx context.Context, baseURL string, i int) (*cose.Sign1Tag[VoucherEntryPayload], error) {
	// Define request structure
	msg := struct {
		OVEntryNum int
	}{
		OVEntryNum: i,
	}

	// Make request
	typ, resp, err := c.Transport.Send(ctx, baseURL, to2GetOVNextEntryMsgType, msg, nil)
	if err != nil {
		return nil, fmt.Errorf("error sending TO2.GetOVNextEntry: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Enforce MaxDeviceMessageSize
	resp = struct {
		io.Reader
		io.Closer
	}{
		Reader: io.LimitReader(resp, int64(c.MaxServiceInfoSizeReceive)),
		Closer: resp,
	}

	// Parse response
	switch typ {
	case to2OVNextEntryMsgType:
		captureMsgType(ctx, typ)
		var ovNextEntry struct {
			OVEntryNum int
			OVEntry    cose.Sign1Tag[VoucherEntryPayload]
		}
		if err := cbor.NewDecoder(resp).Decode(&ovNextEntry); err != nil {
			captureErr(ctx, messageBodyErrCode, "")
			return nil, fmt.Errorf("error parsing TO2.OVNextEntry contents: %w", err)
		}
		if j := ovNextEntry.OVEntryNum; j != i {
			return nil, fmt.Errorf("TO2.OVNextEntry message contained entry number %d, requested %d", j, i)
		}
		return &ovNextEntry.OVEntry, nil

	case ErrorMsgType:
		var errMsg ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return nil, fmt.Errorf("error parsing error message contents of TO2.GetOVNextEntry response: %w", err)
		}
		return nil, fmt.Errorf("error received from TO2.GetOVNextEntry request: %w", errMsg)

	default:
		captureErr(ctx, messageBodyErrCode, "")
		return nil, fmt.Errorf("unexpected message type for response to TO2.GetOVNextEntry: %d", typ)
	}
}

// ProveDevice(64) -> SetupDevice(65)
func (c *Client) proveDevice(ctx context.Context, baseURL string, proveDeviceNonce Nonce, session kex.Session) (Nonce, *VoucherHeader, error) {
	// Generate a new nonce
	var setupDeviceNonce Nonce
	if _, err := rand.Read(setupDeviceNonce[:]); err != nil {
		return Nonce{}, nil, fmt.Errorf("error generating new nonce for TO2.ProveDevice request: %w", err)
	}

	// Define request structure
	paramB, err := session.Parameter(rand.Reader)
	if err != nil {
		return Nonce{}, nil, fmt.Errorf("error generating key exchange session parameters: %w", err)
	}
	eatPayload := struct {
		KeyExchangeB []byte
	}{
		KeyExchangeB: paramB,
	}
	if err != nil {
		return Nonce{}, nil, fmt.Errorf("error creating header for EAT int TO2.ProveDevice: %w", err)
	}
	token := cose.Sign1[eatoken]{
		Header: cose.Header{
			Unprotected: map[cose.Label]any{
				eatUnprotectedNonceClaim: setupDeviceNonce,
			},
		},
		Payload: cbor.NewBstr(newEAT(c.Cred.GUID, proveDeviceNonce, eatPayload, nil)),
	}
	opts, err := signOptsFor(c.Key, c.PSS)
	if err != nil {
		return Nonce{}, nil, fmt.Errorf("error determining signing options for TO2.ProveDevice: %w", err)
	}
	if err := token.Sign(c.Key, nil, opts); err != nil {
		return Nonce{}, nil, fmt.Errorf("error signing EAT payload for TO2.ProveDevice: %w", err)
	}
	msg := token.Tag()

	// Make request
	typ, resp, err := c.Transport.Send(ctx, baseURL, to2ProveDeviceMsgType, msg, session)
	if err != nil {
		return Nonce{}, nil, fmt.Errorf("error sending TO2.ProveDevice: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Enforce MaxDeviceMessageSize
	resp = struct {
		io.Reader
		io.Closer
	}{
		Reader: io.LimitReader(resp, int64(c.MaxServiceInfoSizeReceive)),
		Closer: resp,
	}

	// Parse response
	switch typ {
	case to2SetupDeviceMsgType:
		captureMsgType(ctx, typ)
		var setupDevice cose.Sign1Tag[struct {
			RendezvousInfo  [][]RvInstruction // RendezvousInfo replacement
			GUID            GUID              // GUID replacement
			NonceTO2SetupDv Nonce             // proves freshness of signature
			Owner2Key       PublicKey         // Replacement for Owner key
		}]
		if err := cbor.NewDecoder(resp).Decode(&setupDevice); err != nil {
			captureErr(ctx, messageBodyErrCode, "")
			return Nonce{}, nil, fmt.Errorf("error parsing TO2.SetupDevice contents: %w", err)
		}
		if setupDevice.Payload.Val.NonceTO2SetupDv != setupDeviceNonce {
			captureErr(ctx, invalidMessageErrCode, "")
			return Nonce{}, nil, fmt.Errorf("nonce in TO2.SetupDevice did not match nonce sent in TO2.ProveDevice")
		}
		return setupDeviceNonce, &VoucherHeader{
			GUID:            setupDevice.Payload.Val.GUID,
			RvInfo:          setupDevice.Payload.Val.RendezvousInfo,
			ManufacturerKey: setupDevice.Payload.Val.Owner2Key,
		}, nil

	case ErrorMsgType:
		var errMsg ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return Nonce{}, nil, fmt.Errorf("error parsing error message contents of TO2.ProveDevice response: %w", err)
		}
		return Nonce{}, nil, fmt.Errorf("error received from TO2.ProveDevice request: %w", errMsg)

	default:
		captureErr(ctx, messageBodyErrCode, "")
		return Nonce{}, nil, fmt.Errorf("unexpected message type for response to TO2.ProveDevice: %d", typ)
	}
}

// DeviceServiceInfoReady(66) -> OwnerServiceInfoReady(67)
func (c *Client) readyServiceInfo(ctx context.Context, baseURL string, replacementOVH *VoucherHeader, session kex.Session) (maxDeviceServiceInfoSiz uint16, err error) {
	// Calculate the new OVH HMac similar to DI.SetHMAC
	var replacementHmac Hmac
	if c.Hmac.Supports(HmacSha384Hash) {
		replacementHmac, err = hmacHash(c.Hmac, HmacSha384Hash, replacementOVH)
	} else {
		replacementHmac, err = hmacHash(c.Hmac, HmacSha256Hash, replacementOVH)
	}
	if err != nil {
		return 0, fmt.Errorf("error computing HMAC of ownership voucher header: %w", err)
	}

	// Define request structure
	var msg struct {
		Hmac                    Hmac
		MaxOwnerServiceInfoSize uint16 // maximum size service info that Device can receive
	}
	msg.Hmac = replacementHmac
	msg.MaxOwnerServiceInfoSize = c.MaxServiceInfoSizeReceive

	// Make request
	typ, resp, err := c.Transport.Send(ctx, baseURL, to2DeviceServiceInfoReadyMsgType, msg, session)
	if err != nil {
		return 0, fmt.Errorf("error sending TO2.DeviceServiceInfoReady: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Enforce MaxDeviceMessageSize
	resp = struct {
		io.Reader
		io.Closer
	}{
		Reader: io.LimitReader(resp, int64(c.MaxServiceInfoSizeReceive)),
		Closer: resp,
	}

	// Parse response
	switch typ {
	case to2OwnerServiceInfoReadyMsgType:
		captureMsgType(ctx, typ)
		var ownerServiceInfoReady struct {
			MaxDeviceServiceInfoSize *uint16 // maximum size service info that Owner can receive
		}
		if err := cbor.NewDecoder(resp).Decode(&ownerServiceInfoReady); err != nil {
			captureErr(ctx, messageBodyErrCode, "")
			return 0, fmt.Errorf("error parsing TO2.OwnerServiceInfoReady contents: %w", err)
		}
		if ownerServiceInfoReady.MaxDeviceServiceInfoSize == nil {
			return serviceinfo.DefaultMTU, nil
		}
		return *ownerServiceInfoReady.MaxDeviceServiceInfoSize, nil

	case ErrorMsgType:
		var errMsg ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return 0, fmt.Errorf("error parsing error message contents of TO2.OwnerServiceInfoReady response: %w", err)
		}
		return 0, fmt.Errorf("error received from TO2.DeviceServiceInfoReady request: %w", errMsg)

	default:
		captureErr(ctx, messageBodyErrCode, "")
		return 0, fmt.Errorf("unexpected message type for response to TO2.DeviceServiceInfoReady: %d", typ)
	}
}

// loop[DeviceServiceInfo(68) -> OwnerServiceInfo(69)]
// Done(70) -> Done2(71)
func (c *Client) exchangeServiceInfo(ctx context.Context,
	baseURL string,
	proveDvNonce, setupDvNonce Nonce,
	mtu uint16,
	initInfo *serviceinfo.ChunkReader,
	fsims map[string]serviceinfo.Module,
	session kex.Session,
) error {
	defer func() { _ = initInfo.Close() }()

	// Shadow context to ensure that any goroutines still running after this
	// function exits will shutdown
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// TODO: Limit to 1e6 (1 million) rounds and fail TO2 if exceeded
	deviceServiceInfoOut := initInfo
	for {
		ownerServiceInfoOut, ownerServiceInfoIn := serviceinfo.NewChunkInPipe()
		nextDeviceServiceInfoOut, deviceServiceInfoIn := serviceinfo.NewChunkOutPipe()

		// The goroutine is started before sending DeviceServiceInfo, which
		// writes to the owner service info (unbuffered) pipe.
		go handleFSIMs(ctx, mtu, fsims, deviceServiceInfoIn, ownerServiceInfoOut)

		// Send all device service info and get all owner service info
		done, err := c.exchangeServiceInfoRound(ctx, baseURL, mtu, deviceServiceInfoOut, ownerServiceInfoIn, session)
		if err != nil {
			return err
		}

		// Stop loop only once owner indicates it is done
		if done {
			break
		}

		// Set the device service info to send on the next loop iteration
		// (populated by the goroutine in this iteration)
		deviceServiceInfoOut = nextDeviceServiceInfoOut
	}

	// Finalize TO2 by sending Done message
	msg := struct {
		NonceTO2ProveDv Nonce
	}{
		NonceTO2ProveDv: proveDvNonce,
	}

	// Make request
	typ, resp, err := c.Transport.Send(ctx, baseURL, to2DoneMsgType, msg, session)
	if err != nil {
		return fmt.Errorf("error sending TO2.Done: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Enforce MaxDeviceMessageSize
	resp = struct {
		io.Reader
		io.Closer
	}{
		Reader: io.LimitReader(resp, int64(c.MaxServiceInfoSizeReceive)),
		Closer: resp,
	}

	// Parse response
	switch typ {
	case to2Done2MsgType:
		captureMsgType(ctx, typ)
		var done2 struct {
			NonceTO2SetupDv Nonce
		}
		if err := cbor.NewDecoder(resp).Decode(&done2); err != nil {
			captureErr(ctx, messageBodyErrCode, "")
			return fmt.Errorf("error parsing TO2.Done2 contents: %w", err)
		}
		if done2.NonceTO2SetupDv != setupDvNonce {
			captureErr(ctx, invalidMessageErrCode, "")
			return fmt.Errorf("nonce received in TO2.Done2 message did not match nonce received in TO2.SetupDevice")
		}
		return nil

	case ErrorMsgType:
		var errMsg ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return fmt.Errorf("error parsing error message contents of TO2.Done response: %w", err)
		}
		return fmt.Errorf("error received from TO2.Done request: %w", errMsg)

	default:
		captureErr(ctx, messageBodyErrCode, "")
		return fmt.Errorf("unexpected message type for response to TO2.Done: %d", typ)
	}
}

// Handle owner service info with FSIMs. This must be run in a goroutine,
// because the chunking/unchunking pipes are not buffered.
func handleFSIMs(ctx context.Context, mtu uint16, fsims map[string]serviceinfo.Module, send *serviceinfo.UnchunkWriter, recv *serviceinfo.UnchunkReader) {
	defer func() { _ = send.Close() }()
	for {
		// Get next service info from the owner service
		key, info, ok := recv.NextServiceInfo()
		if !ok {
			return
		}
		moduleName, messageName, _ := strings.Cut(key, ":")

		// Lookup FSIM to use for handling service info
		fsim, ok := fsims[moduleName]
		if !ok {
			// Section 3.8.3.1 says to ignore all messages for unknown modules,
			// except message=active, which should respond CBOR false
			if messageName == "active" {
				if err := send.NextServiceInfo(moduleName, messageName); err != nil {
					_ = send.CloseWithError(err)
					return
				}
				if err := cbor.NewEncoder(send).Encode(false); err != nil {
					_ = send.CloseWithError(err)
					return
				}
			}
			continue
		}

		// Use FSIM handler and provide it a function which can be used to send
		// zero or more service info KVs. If the FSIM handler returns an error
		// then the pipe will be closed with an error, causing the error to
		// propagate to the chunk reader, which is used in the ServiceInfo send
		// loop.
		//
		// The function provided to each FSIM handler returns a writer to write
		// the value part of the service info KV. This writer is buffered and
		// automatically flushed when the handler returns or another service
		// info is to be sent.
		buf := bufio.NewWriterSize(send, int(mtu))
		if err := fsim.HandleFSIM(ctx, messageName, info, func(moduleName, messageName string) io.Writer {
			if err := buf.Flush(); err != nil {
				_ = send.CloseWithError(err)
			}
			if err := send.NextServiceInfo(moduleName, messageName); err != nil {
				_ = send.CloseWithError(err)
			}
			return buf
		}); err != nil {
			_ = send.CloseWithError(err)
			return
		}
		if err := buf.Flush(); err != nil {
			_ = send.CloseWithError(err)
			return
		}
	}
}

type sendServiceInfo struct {
	IsMoreServiceInfo bool
	ServiceInfo       []*serviceinfo.KV
}

type recvServiceInfo struct {
	IsMoreServiceInfo bool
	IsDone            bool
	ServiceInfo       []*serviceinfo.KV
}

// Perform one iteration of send all device service info (may be across
// multiple FDO messages) and receive all owner service info (same applies).
func (c *Client) exchangeServiceInfoRound(ctx context.Context, baseURL string, mtu uint16,
	r *serviceinfo.ChunkReader, w *serviceinfo.ChunkWriter, session kex.Session,
) (bool, error) {
	// Ensure w is always closed so that FSIM handling goroutine doesn't
	// deadlock
	defer func() { _ = w.Close() }()

	// Subtract 3 bytes from MTU to account for a CBOR header indicating "array
	// of 256-65535 items"
	mtu -= 3

	// Create DeviceServiceInfo request structure
	var msg sendServiceInfo
	maxRead := mtu
	for {
		chunk, err := r.ReadChunk(maxRead)
		if errors.Is(err, io.EOF) {
			break
		}
		if errors.Is(err, serviceinfo.ErrSizeTooSmall) {
			if maxRead == mtu {
				return false, fmt.Errorf("MTU too small to send ServiceInfo: malicious large key string?")
			}
			msg.IsMoreServiceInfo = true
			break
		}
		if err != nil {
			return false, fmt.Errorf("error reading KV to send to owner: %w", err)
		}
		maxRead -= chunk.Size()
		msg.ServiceInfo = append(msg.ServiceInfo, chunk)
	}

	// Send request
	ownerServiceInfo, err := c.deviceServiceInfo(ctx, baseURL, msg, session)
	if err != nil {
		return false, err
	}

	// Receive all owner service info
	for _, kv := range ownerServiceInfo.ServiceInfo {
		if err := w.WriteChunk(kv); err != nil {
			_ = w.CloseWithError(err)
			return false, fmt.Errorf("error piping owner service info to FSIM: %w", err)
		}
	}

	// If no more owner service info, close the pipe
	if !ownerServiceInfo.IsMoreServiceInfo {
		if err := w.Close(); err != nil {
			return false, fmt.Errorf("error closing owner service info -> FSIM pipe: %w", err)
		}
	}

	// Recurse when there's more service info to send from device or receive
	// from owner
	if msg.IsMoreServiceInfo || ownerServiceInfo.IsMoreServiceInfo {
		return c.exchangeServiceInfoRound(ctx, baseURL, mtu, r, w, session)
	}

	return ownerServiceInfo.IsDone, nil
}

// DeviceServiceInfo(68) -> OwnerServiceInfo(69)
func (c *Client) deviceServiceInfo(ctx context.Context, baseURL string, msg sendServiceInfo, session kex.Session) (*recvServiceInfo, error) {
	// If there is no ServiceInfo to send and the last owner response did not
	// indicate IsMore, then this is just a regular interval check to see if
	// owner IsDone. In this case, add a delay to avoid clobbering the owner
	// service.
	//
	// TODO: Make delay configurable
	if len(msg.ServiceInfo) == 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}

	// Make request
	typ, resp, err := c.Transport.Send(ctx, baseURL, to2DeviceServiceInfoMsgType, msg, session)
	if err != nil {
		return nil, fmt.Errorf("error sending TO2.DeviceServiceInfo: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Enforce MaxDeviceMessageSize
	resp = struct {
		io.Reader
		io.Closer
	}{
		Reader: io.LimitReader(resp, int64(c.MaxServiceInfoSizeReceive)),
		Closer: resp,
	}

	// Parse response
	switch typ {
	case to2OwnerServiceInfoMsgType:
		captureMsgType(ctx, typ)
		var ownerServiceInfo recvServiceInfo
		if err := cbor.NewDecoder(resp).Decode(&ownerServiceInfo); err != nil {
			captureErr(ctx, messageBodyErrCode, "")
			return nil, fmt.Errorf("error parsing TO2.OwnerServiceInfo contents: %w", err)
		}
		return &ownerServiceInfo, nil

	case ErrorMsgType:
		var errMsg ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return nil, fmt.Errorf("error parsing error message contents of TO2.OwnerServiceInfo response: %w", err)
		}
		return nil, fmt.Errorf("error received from TO2.DeviceServiceInfo request: %w", errMsg)

	default:
		captureErr(ctx, messageBodyErrCode, "")
		return nil, fmt.Errorf("unexpected message type for response to TO2.DeviceServiceInfo: %d", typ)
	}
}
