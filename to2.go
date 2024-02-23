// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"

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
func (c *Client) verifyOwner(ctx context.Context, baseURL string, to1d *cose.Sign1[To1d, []byte]) (Nonce, *VoucherHeader, kex.Session, error) {
	// Construct ownership voucher from parts received from the owner service
	proveDeviceNonce, info, session, err := c.helloDevice(ctx, baseURL)
	if err != nil {
		return Nonce{}, nil, nil, err
	}
	if info.NumVoucherEntries == 0 {
		return Nonce{}, nil, nil, fmt.Errorf("ownership voucher cannot have zero entries")
	}
	var entries []cose.Sign1Tag[VoucherEntryPayload, []byte]
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

	// If no to1d blob was given, then immmediately return. This will be the
	// case when RV bypass was used.
	if to1d == nil {
		return proveDeviceNonce, &info.OVH, session, nil
	}

	// If the TO1.RVRedirect signature does not verify, the Device must assume
	// that a man in the middle is monitoring its traffic, and fail TO2
	// immediately with an error code message.
	if ok, err := to1d.Verify(expectedOwnerPub, nil, nil); err != nil {
		captureErr(ctx, invalidMessageErrCode, "")
		return Nonce{}, nil, nil, fmt.Errorf("error verifying to1d signature: %w", err)
	} else if !ok {
		captureErr(ctx, invalidMessageErrCode, "")
		return Nonce{}, nil, nil, fmt.Errorf("%w: to1d signature verification failed", ErrCryptoVerifyFailed)
	}

	return proveDeviceNonce, &info.OVH, session, nil
}

type helloDeviceMsg struct {
	MaxDeviceMessageSize uint16
	GUID                 GUID
	NonceTO2ProveOV      Nonce
	KexSuiteName         kex.Suite
	CipherSuite          kex.CipherSuiteID
	SigInfoA             sigInfo
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
	hello := helloDeviceMsg{
		MaxDeviceMessageSize: 65535, // TODO: Make this configurable and match transport config
		GUID:                 c.Cred.GUID,
		NonceTO2ProveOV:      proveOVNonce,
		KexSuiteName:         c.KeyExchange,
		CipherSuite:          c.CipherSuite,
		SigInfoA:             *aSigInfo,
	}

	// Make a request
	typ, resp, err := c.Transport.Send(ctx, baseURL, to2HelloDeviceMsgType, hello, nil)
	if err != nil {
		return Nonce{}, nil, nil, err
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	var proveOVHdr cose.Sign1Tag[ovhProof, []byte]
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
	if err := cbor.NewEncoder(helloDeviceHash).Encode(hello); err != nil {
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
	if ok, err := proveOVHdr.Verify(key, nil, nil); err != nil {
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

type ovhProof struct {
	OVH                 cbor.Bstr[VoucherHeader]
	NumOVEntries        uint8
	OVHHmac             Hmac
	NonceTO2ProveOV     Nonce
	SigInfoB            sigInfo
	KeyExchangeA        []byte
	HelloDeviceHash     Hash
	MaxOwnerMessageSize uint16
}

// HelloDevice(60) -> ProveOVHdr(61)
//
// TODO: Handle MaxDeviceMessageSize
func (s *Server) proveOVHdr(ctx context.Context, msg io.Reader) (*cose.Sign1Tag[ovhProof, []byte], error) {
	// Parse request
	var rawHello cbor.RawBytes
	if err := cbor.NewDecoder(msg).Decode(&rawHello); err != nil {
		return nil, fmt.Errorf("error decoding TO2.HelloDevice request: %w", err)
	}
	helloSum256 := sha256.Sum256(rawHello)
	var hello helloDeviceMsg
	if err := cbor.Unmarshal(rawHello, &hello); err != nil {
		return nil, fmt.Errorf("error decoding TO2.HelloDevice request: %w", err)
	}

	// Retrieve voucher
	if err := s.Proofs.SetGUID(ctx, hello.GUID); err != nil {
		return nil, fmt.Errorf("error associating device GUID to proof session: %w", err)
	}
	ov, err := s.Devices.Voucher(ctx, hello.GUID)
	if err != nil {
		captureErr(ctx, resourceNotFound, "")
		return nil, fmt.Errorf("error retrieving voucher for device %x: %w", hello.GUID, err)
	}

	// Generate nonce for ProveDevice
	var proveDeviceNonce Nonce
	if _, err := rand.Read(proveDeviceNonce[:]); err != nil {
		return nil, fmt.Errorf("error generating new nonce for TO2.ProveOVHdr response: %w", err)
	}
	if err := s.Nonces.SetProveDeviceNonce(ctx, proveDeviceNonce); err != nil {
		return nil, fmt.Errorf("error storing nonce for later use in TO2.Done: %w", err)
	}

	// Begin key exchange
	if !kex.IsValid(hello.KexSuiteName, hello.CipherSuite) {
		return nil, fmt.Errorf("unsupported key exchange/cipher suite")
	}
	sess := hello.KexSuiteName.New(nil, hello.CipherSuite)
	xA, err := sess.Parameter(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("error generating client key exchange parameter: %w", err)
	}
	if err := s.KeyExchange.SetSession(ctx, hello.KexSuiteName, sess); err != nil {
		return nil, fmt.Errorf("error storing key exchange session: %w", err)
	}

	// Send begin proof
	keyType, opts, err := keyTypeFor(hello.SigInfoA.Type)
	if err != nil {
		return nil, fmt.Errorf("error getting key type from device sig info: %w", err)
	}
	if mfgKeyType := ov.Header.Val.ManufacturerKey.Type; keyType != mfgKeyType {
		return nil, fmt.Errorf("device sig info has key type %q, must be %q to match manufacturer key", keyType, mfgKeyType)
	}
	key, ok := s.OwnerKeys.Signer(keyType)
	if !ok {
		return nil, fmt.Errorf("key type %s not supported", keyType)
	}
	ownerPublicKey, err := newPublicKey(keyType, key.Public())
	if err != nil {
		return nil, fmt.Errorf("error with owner public key: %w", err)
	}
	s1 := cose.Sign1[ovhProof, []byte]{
		Header: cose.Header{
			Unprotected: map[cose.Label]any{
				to2NonceClaim:       proveDeviceNonce,
				to2OwnerPubKeyClaim: ownerPublicKey,
			},
		},
		Payload: cbor.NewByteWrap(ovhProof{
			OVH:             ov.Header,
			NumOVEntries:    uint8(len(ov.Entries)),
			OVHHmac:         ov.Hmac,
			NonceTO2ProveOV: hello.NonceTO2ProveOV,
			SigInfoB:        hello.SigInfoA,
			KeyExchangeA:    xA,
			HelloDeviceHash: Hash{
				Algorithm: Sha256Hash,
				Value:     helloSum256[:],
			},
			MaxOwnerMessageSize: 65535, // TODO: Make this configurable and match handler config
		}),
	}
	if err := s1.Sign(key, nil, nil, opts); err != nil {
		return nil, fmt.Errorf("error signing TO2.ProveOVHdr payload: %w", err)
	}

	return s1.Tag(), nil
}

// GetOVNextEntry(62) -> OVNextEntry(63)
func (c *Client) nextOVEntry(ctx context.Context, baseURL string, i int) (*cose.Sign1Tag[VoucherEntryPayload, []byte], error) {
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

	// Parse response
	switch typ {
	case to2OVNextEntryMsgType:
		captureMsgType(ctx, typ)
		var ovNextEntry ovEntry
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

type ovEntry struct {
	OVEntryNum int
	OVEntry    cose.Sign1Tag[VoucherEntryPayload, []byte]
}

// GetOVNextEntry(62) -> OVNextEntry(63)
func (s *Server) ovNextEntry(ctx context.Context, msg io.Reader) (*ovEntry, error) {
	// Parse request
	var nextEntry struct {
		OVEntryNum int
	}
	if err := cbor.NewDecoder(msg).Decode(&nextEntry); err != nil {
		return nil, fmt.Errorf("error decoding TO2.GetOVNextEntry request: %w", err)
	}

	// Retrieve voucher
	guid, err := s.Proofs.GUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving associated device GUID of proof session: %w", err)
	}
	ov, err := s.Devices.Voucher(ctx, guid)
	if err != nil {
		return nil, fmt.Errorf("error retrieving voucher for device %x: %w", guid, err)
	}

	// Return entry
	if len(ov.Entries) < nextEntry.OVEntryNum {
		return nil, fmt.Errorf("invalid ownership voucher entry index %d", nextEntry.OVEntryNum)
	}
	return &ovEntry{
		OVEntryNum: nextEntry.OVEntryNum,
		OVEntry:    ov.Entries[nextEntry.OVEntryNum],
	}, nil
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
	token := cose.Sign1[eatoken, []byte]{
		Header: cose.Header{
			Unprotected: map[cose.Label]any{
				eatUnprotectedNonceClaim: setupDeviceNonce,
			},
		},
		Payload: cbor.NewByteWrap(newEAT(c.Cred.GUID, proveDeviceNonce, eatPayload, nil)),
	}
	opts, err := signOptsFor(c.Key, c.PSS)
	if err != nil {
		return Nonce{}, nil, fmt.Errorf("error determining signing options for TO2.ProveDevice: %w", err)
	}
	if err := token.Sign(c.Key, nil, nil, opts); err != nil {
		return Nonce{}, nil, fmt.Errorf("error signing EAT payload for TO2.ProveDevice: %w", err)
	}
	msg := token.Tag()

	// Make request
	typ, resp, err := c.Transport.Send(ctx, baseURL, to2ProveDeviceMsgType, msg, kex.DecryptOnly{Session: session})
	if err != nil {
		return Nonce{}, nil, fmt.Errorf("error sending TO2.ProveDevice: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	switch typ {
	case to2SetupDeviceMsgType:
		captureMsgType(ctx, typ)
		var setupDevice cose.Sign1Tag[deviceSetup, []byte]
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

type deviceSetup struct {
	RendezvousInfo  [][]RvInstruction // RendezvousInfo replacement
	GUID            GUID              // GUID replacement
	NonceTO2SetupDv Nonce             // proves freshness of signature
	Owner2Key       PublicKey         // Replacement for Owner key
}

// ProveDevice(64) -> SetupDevice(65)
//
//nolint:gocyclo, This is very complex validation that is better understood linearly
func (s *Server) setupDevice(ctx context.Context, msg io.Reader) (*cose.Sign1Tag[deviceSetup, []byte], error) {
	// Parse request
	var proof cose.Sign1Tag[eatoken, []byte]
	if err := cbor.NewDecoder(msg).Decode(&proof); err != nil {
		return nil, fmt.Errorf("error decoding TO2.ProveDevice request: %w", err)
	}

	// Parse and store SetupDevice nonce
	var setupDeviceNonce Nonce
	if ok, err := proof.Unprotected.Parse(eatUnprotectedNonceClaim, &setupDeviceNonce); err != nil {
		return nil, fmt.Errorf("error parsing SetupDevice nonce from TO2.ProveDevice request unprotected header: %w", err)
	} else if !ok {
		return nil, fmt.Errorf("TO2.ProveDevice request missing SetupDevice nonce in unprotected headers")
	}
	if err := s.Nonces.SetSetupDeviceNonce(ctx, setupDeviceNonce); err != nil {
		return nil, fmt.Errorf("error storing SetupDevice nonce from TO2.ProveDevice request: %w", err)
	}

	// Retrieve voucher
	guid, err := s.Proofs.GUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving associated device GUID of proof session: %w", err)
	}
	ov, err := s.Devices.Voucher(ctx, guid)
	if err != nil {
		return nil, fmt.Errorf("error retrieving voucher for device %x: %w", guid, err)
	}

	// Verify request signature based on device certificate chain in voucher
	devicePublicKey, err := ov.DevicePublicKey()
	if err != nil {
		return nil, fmt.Errorf("error parsing device public key from ownership voucher: %w", err)
	}
	if ok, err := proof.Verify(devicePublicKey, nil, nil); err != nil {
		return nil, fmt.Errorf("error verifying signature of device EAT: %w", err)
	} else if !ok {
		return nil, fmt.Errorf("device EAT verification failed")
	}

	// Validate EAT contents
	proveDeviceNonce, err := s.Nonces.ProveDeviceNonce(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving ProveDevice nonce for session: %w", err)
	}
	eat := proof.Payload.Val
	nonceClaim, ok := eat[eatNonceClaim].([]byte)
	if !ok {
		return nil, fmt.Errorf("missing nonce claim from EAT")
	}
	if !bytes.Equal(nonceClaim, proveDeviceNonce[:]) {
		return nil, fmt.Errorf("nonce claim from EAT does not match ProveDevice nonce")
	}
	ueidClaim, ok := eat[eatUeidClaim].([]byte)
	if !ok {
		return nil, fmt.Errorf("missing UEID claim from EAT")
	}
	if !bytes.Equal(ueidClaim, append([]byte{eatRandUeid}, guid[:]...)) {
		return nil, fmt.Errorf("claim of UEID in EAT does not match the device GUID")
	}
	fdoClaim, ok := eat[eatFdoClaim].([]any)
	if !ok || len(fdoClaim) != 1 {
		return nil, fmt.Errorf("missing FDO claim from EAT")
	}

	// Complete key exchange using EAT FDO claim
	xB, ok := fdoClaim[0].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid EAT FDO claim: expected one item of type []byte")
	}
	token, ok := s.State.TokenFromContext(ctx)
	if !ok {
		panic("programming error - token missing from context")
	}
	suite, sess, err := s.KeyExchange.Session(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("error getting associated key exchange session: %w", err)
	}
	if err := sess.SetParameter(xB); err != nil {
		return nil, fmt.Errorf("error completing key exchange: %w", err)
	}
	if err := s.KeyExchange.SetSession(ctx, suite, sess); err != nil {
		return nil, fmt.Errorf("error updating associated key exchange session: %w", err)
	}

	// Generate a replacement GUID
	var replacementGUID GUID
	if _, err := rand.Read(replacementGUID[:]); err != nil {
		return nil, fmt.Errorf("error generating replacement GUID for device: %w", err)
	}
	if err := s.Replacements.SetReplacementGUID(ctx, replacementGUID); err != nil {
		return nil, fmt.Errorf("error storing replacement GUID for device: %w", err)
	}

	// Respond with device setup
	keyType := ov.Header.Val.ManufacturerKey.Type
	key, ok := s.OwnerKeys.Signer(keyType)
	if !ok {
		return nil, fmt.Errorf("key type %s not supported", keyType)
	}
	ownerPublicKey, err := newPublicKey(keyType, key.Public())
	if err != nil {
		return nil, fmt.Errorf("error with owner public key: %w", err)
	}
	s1 := cose.Sign1[deviceSetup, []byte]{
		Payload: cbor.NewByteWrap(deviceSetup{
			RendezvousInfo:  s.RvInfo,
			GUID:            replacementGUID,
			NonceTO2SetupDv: setupDeviceNonce,
			Owner2Key:       *ownerPublicKey,
		}),
	}
	opts, err := signOptsFor(key, keyType == RsaPssKeyType)
	if err != nil {
		return nil, fmt.Errorf("error determining signing options for TO2.SetupDevice message: %w", err)
	}
	if err := s1.Sign(key, nil, nil, opts); err != nil {
		return nil, fmt.Errorf("error signing TO2.SetupDevice payload: %w", err)
	}
	return s1.Tag(), nil
}

type deviceServiceInfoReady struct {
	Hmac                    *Hmac
	MaxOwnerServiceInfoSize *uint16 // maximum size service info that Device can receive
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
	msg := deviceServiceInfoReady{
		Hmac:                    &replacementHmac,
		MaxOwnerServiceInfoSize: &c.MaxServiceInfoSizeReceive,
	}

	// Make request
	typ, resp, err := c.Transport.Send(ctx, baseURL, to2DeviceServiceInfoReadyMsgType, msg, session)
	if err != nil {
		return 0, fmt.Errorf("error sending TO2.DeviceServiceInfoReady: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	switch typ {
	case to2OwnerServiceInfoReadyMsgType:
		captureMsgType(ctx, typ)
		var ready ownerServiceInfoReady
		if err := cbor.NewDecoder(resp).Decode(&ready); err != nil {
			captureErr(ctx, messageBodyErrCode, "")
			return 0, fmt.Errorf("error parsing TO2.OwnerServiceInfoReady contents: %w", err)
		}
		if ready.MaxDeviceServiceInfoSize == nil {
			return serviceinfo.DefaultMTU, nil
		}
		return *ready.MaxDeviceServiceInfoSize, nil

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

type ownerServiceInfoReady struct {
	MaxDeviceServiceInfoSize *uint16 // maximum size service info that Owner can receive
}

// DeviceServiceInfoReady(66) -> OwnerServiceInfoReady(67)
func (s *Server) ownerServiceInfoReady(ctx context.Context, msg io.Reader) (*ownerServiceInfoReady, error) {
	// Parse request
	var deviceReady deviceServiceInfoReady
	if err := cbor.NewDecoder(msg).Decode(&deviceReady); err != nil {
		return nil, fmt.Errorf("error decoding TO2.DeviceServiceInfoReady request: %w", err)
	}

	// Store new HMAC for voucher replacement
	if deviceReady.Hmac == nil {
		return nil, fmt.Errorf("device did not send a replacement voucher HMAC")
	}
	if err := s.Replacements.SetReplacementHmac(ctx, *deviceReady.Hmac); err != nil {
		return nil, fmt.Errorf("error storing replacement voucher HMAC for device: %w", err)
	}

	// TODO: Set send MTU

	// Send resposne
	ownerReady := new(ownerServiceInfoReady)
	if s.MaxDeviceServiceInfoSize != 0 {
		ownerReady.MaxDeviceServiceInfoSize = &s.MaxDeviceServiceInfoSize
	}
	return ownerReady, nil
}

type doneMsg struct {
	NonceTO2ProveDv Nonce
}

type done2Msg struct {
	NonceTO2SetupDv Nonce
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

	// Subtract 3 bytes from MTU to account for a CBOR header indicating "array
	// of 256-65535 items" and 2 more bytes for "array of two" plus the first
	// item indicating "IsMoreServiceInfo"
	mtu -= 5

	// TODO: Limit to 1e6 (1 million) rounds and fail TO2 if exceeded
	deviceServiceInfoOut := initInfo
	for {
		// Buffer service info send and receive queues. This buffer may grow
		// indefinitely if FSIMs are not well behaved. For example, if an owner
		// service sends 100s of upload requests, the requests will be
		// processed as they are received and may fill up the send buffer until
		// the device is out of memory.
		//
		// While in this case, it may seem obvious that the upload requests
		// should be buffered and then processed rather than handled
		// sequentially, it would be equally unsafe to implement this behavior,
		// because the request buffer may also grow past the MTU if
		// IsMoreServiceInfo is used, keeping the device from processing its
		// received service info.
		//
		// In the end, there's no general way to exchange arbitrary data
		// between two parties where each piece of data one party receives may
		// cause it to put any number of pieces of data on its send queue and
		// the other party gets to choose when it may flush its queue.
		//
		// Buffering both queues and relying on good behavior of FSIMs is the
		// best and only real option. Both queues should be buffered because
		// there can be an asymmetric use of queues in either direction. Many
		// file upload requests results in a small device receive queue and
		// large device send queue. Many file downloads result in the opposite.

		// 1000 service info buffered in and out means up to ~1MB of data for
		// the default MTU. If both queues fill, the device will deadlock. This
		// should only happen for a poorly behaved FSIM.
		ownerServiceInfoOut, ownerServiceInfoIn := serviceinfo.NewChunkInPipe(1000)
		nextDeviceServiceInfoOut, deviceServiceInfoIn := serviceinfo.NewChunkOutPipe(1000)

		// The goroutine is started before sending DeviceServiceInfo, which
		// writes to the owner service info (unbuffered) pipe.
		modules := fsimMap{modules: fsims, active: make(map[string]bool)}
		go handleFSIMs(ctx, mtu, modules, deviceServiceInfoIn, ownerServiceInfoOut)

		// Send all device service info and receive all owner service info into
		// a buffered chan
		done, err := c.exchangeServiceInfoRound(ctx, baseURL, mtu, deviceServiceInfoOut, ownerServiceInfoIn, session)
		if err != nil {
			_ = ownerServiceInfoIn.CloseWithError(err)
			return err
		}

		// If there is no ServiceInfo to send and the last owner response did
		// not contain any service info, then this is just a regular interval
		// check to see if owner IsDone. In this case, add a delay to avoid
		// clobbering the owner service.
		//
		// TODO: Wait a few seconds if no service info was sent or received in
		// the last round.

		// Stop loop only once owner indicates it is done
		if done {
			break
		}

		// Set the device service info to send on the next loop iteration
		// (populated by the goroutine in this iteration)
		deviceServiceInfoOut = nextDeviceServiceInfoOut
	}

	// Finalize TO2 by sending Done message
	msg := doneMsg{
		NonceTO2ProveDv: proveDvNonce,
	}

	// Make request
	typ, resp, err := c.Transport.Send(ctx, baseURL, to2DoneMsgType, msg, session)
	if err != nil {
		return fmt.Errorf("error sending TO2.Done: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	switch typ {
	case to2Done2MsgType:
		captureMsgType(ctx, typ)
		var done2 done2Msg
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
func handleFSIMs(ctx context.Context, mtu uint16, modules fsimMap, send *serviceinfo.UnchunkWriter, recv *serviceinfo.UnchunkReader) {
	var writeChans []chan chan struct{}
	for {
		// Get next service info from the owner service and handle it.
		key, messageBody, ok := recv.NextServiceInfo()
		if !ok {
			_ = send.Close()
			break
		}

		// Automatically receive and respond to active messages. This send is
		// expected to be buffered until all receives are processed, unlike
		// modules which must wait for all receives to occur before sending.
		// This is allowed because the data is small and the send buffer is
		// large enough for many more "active" responses than is practical to
		// expect in the real world.
		moduleName, messageName, _ := strings.Cut(key, ":")
		fsim, active := modules.Lookup(moduleName)
		if messageName == "active" {
			// Receive active message of true or false
			prevActive, active := active, false
			if err := cbor.NewDecoder(messageBody).Decode(&active); err != nil {
				_ = send.CloseWithError(err)
				return
			}
			_, _ = io.Copy(io.Discard, messageBody)

			// Transition internal state
			modules.active[moduleName] = active
			fsim.Transition(active)

			// Send active message when appropriate
			if active && !prevActive {
				if err := sendActive(ctx, moduleName, active, fsim, send); err != nil {
					_ = send.CloseWithError(err)
					return
				}
			}
			continue
		}

		// Use FSIM handler and provide it a function which can be used to send
		// zero or more service info KVs. The function returns a writer to
		// write the value part of the service info KV. This writer is buffered
		// and automatically flushed when the handler returns or another
		// service info is to be sent.
		//
		// If the FSIM handler returns an error then the pipe will be closed
		// with an error, causing the error to propagate to the chunk reader,
		// which is used in the ServiceInfo send loop.
		//
		// The FSIM is handled in a goroutine, allowing service info to be read
		// and processed in parallel, but sends are serialized via a channel
		// letting it know when to start and indicate back when writing is
		// complete.
		readyToWrite := make(chan chan struct{})
		writeChans = append(writeChans, readyToWrite)
		go handleFSIM(ctx, fsim, moduleName, messageName, messageBody, send, mtu, readyToWrite)
	}

	// Synchronize writes by sending one done channel at a time and waiting for
	// the receiver to send back done.
	for _, nextWrite := range writeChans {
		done := make(chan struct{})
		select {
		case <-ctx.Done():
			return
		case nextWrite <- done:
		}
		select {
		case <-ctx.Done():
			return
		case <-done:
		}
	}
}

func sendActive(ctx context.Context, moduleName string, active bool, fsim serviceinfo.Module, send *serviceinfo.UnchunkWriter) error {
	if _, isUnknown := fsim.(serviceinfo.UnknownModule); isUnknown && moduleName != devmodModuleName {
		active = false
	}
	if err := send.NextServiceInfo(moduleName, "active"); err != nil {
		return err
	}
	if err := cbor.NewEncoder(send).Encode(active); err != nil {
		return err
	}
	return nil
}

func handleFSIM(ctx context.Context, fsim serviceinfo.Module,
	moduleName, messageName string, messageBody io.Reader,
	send *serviceinfo.UnchunkWriter, mtu uint16, readyToWrite <-chan chan struct{},
) {
	var done chan<- struct{}
	defer func() {
		if done != nil {
			close(done)
		}
	}()
	buf := bufio.NewWriterSize(send, int(mtu))
	if err := fsim.Receive(ctx, moduleName, messageName, messageBody, func(messageName string) io.Writer {
		_ = buf.Flush()
		// Drain messageBody and fail by closing writer with error if any
		// body remains. This is to ensure that writes occur only after
		// reads, thus allowing all service info to be read while response
		// writers wait to be signaled to start writing.
		if _, unsafe := fsim.(serviceinfo.UnsafeModule); !unsafe {
			if n, err := io.Copy(io.Discard, messageBody); err != nil {
				_ = send.CloseWithError(err)
				return send
			} else if n > 0 {
				_ = send.CloseWithError(fmt.Errorf(
					"fsim did not read full body of message '%s:%s'",
					moduleName, messageName))
				return send
			}
		}

		// Wait on channel to synchronize response order
		select {
		case <-ctx.Done():
			_ = send.CloseWithError(ctx.Err())
			return send
		case done = <-readyToWrite:
		}

		_ = send.NextServiceInfo(moduleName, messageName)
		return buf
	}); err != nil {
		_ = send.CloseWithError(err)
		return
	}
	if err := buf.Flush(); err != nil {
		_ = send.CloseWithError(err)
		return
	}

	// Ensure that buffer was drained, even if an unsafe module was used
	if n, err := io.Copy(io.Discard, messageBody); err != nil {
		_ = send.CloseWithError(err)
		return
	} else if n > 0 {
		_ = send.CloseWithError(fmt.Errorf(
			"fsim did not read full body of message '%s:%s'",
			moduleName, messageName))
		return
	}
}

type fsimMap struct {
	modules map[string]serviceinfo.Module
	active  map[string]bool
}

func (fm fsimMap) Lookup(moduleName string) (fsim serviceinfo.Module, active bool) {
	module, known := fm.modules[moduleName]
	if !known {
		module = serviceinfo.UnknownModule{}
	}
	return module, fm.active[moduleName]
}

type deviceServiceInfo struct {
	IsMoreServiceInfo bool
	ServiceInfo       []*serviceinfo.KV
}

type ownerServiceInfo struct {
	IsMoreServiceInfo bool
	IsDone            bool
	ServiceInfo       []*serviceinfo.KV
}

// Perform one iteration of send all device service info (may be across
// multiple FDO messages) and receive all owner service info (same applies).
func (c *Client) exchangeServiceInfoRound(ctx context.Context, baseURL string, mtu uint16,
	r *serviceinfo.ChunkReader, w *serviceinfo.ChunkWriter, session kex.Session,
) (bool, error) {
	// Create DeviceServiceInfo request structure
	var msg deviceServiceInfo
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
			return false, fmt.Errorf("error piping owner service info to FSIM: %w", err)
		}
	}

	// Recurse when there's more service info to send from device or receive
	// from owner without allowing the other side to respond
	if msg.IsMoreServiceInfo || ownerServiceInfo.IsMoreServiceInfo {
		return c.exchangeServiceInfoRound(ctx, baseURL, mtu, r, w, session)
	}

	// If no more owner service info, close the pipe
	if err := w.Close(); err != nil {
		return false, fmt.Errorf("error closing owner service info -> FSIM pipe: %w", err)
	}

	return ownerServiceInfo.IsDone, nil
}

// DeviceServiceInfo(68) -> OwnerServiceInfo(69)
func (c *Client) deviceServiceInfo(ctx context.Context, baseURL string, msg deviceServiceInfo, session kex.Session) (*ownerServiceInfo, error) {
	// Make request
	typ, resp, err := c.Transport.Send(ctx, baseURL, to2DeviceServiceInfoMsgType, msg, session)
	if err != nil {
		return nil, fmt.Errorf("error sending TO2.DeviceServiceInfo: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	switch typ {
	case to2OwnerServiceInfoMsgType:
		captureMsgType(ctx, typ)
		var ownerServiceInfo ownerServiceInfo
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

// DeviceServiceInfo(68) -> OwnerServiceInfo(69)
func (s *Server) ownerServiceInfo(ctx context.Context, msg io.Reader) (*ownerServiceInfo, error) {
	// Parse request
	var deviceInfo deviceServiceInfo
	if err := cbor.NewDecoder(msg).Decode(&deviceInfo); err != nil {
		return nil, fmt.Errorf("error decoding TO2.DeviceServiceInfo request: %w", err)
	}

	// Print out all service info
	for _, info := range deviceInfo.ServiceInfo {
		fmt.Printf("Device service info: %+v\n", info)
	}

	return &ownerServiceInfo{
		IsMoreServiceInfo: false,
		IsDone:            !deviceInfo.IsMoreServiceInfo,
		ServiceInfo:       nil,
	}, nil
}

// Done(70) -> Done2(71)
func (s *Server) to2Done2(ctx context.Context, msg io.Reader) (*done2Msg, error) {
	// Parse request
	var done doneMsg
	if err := cbor.NewDecoder(msg).Decode(&done); err != nil {
		return nil, fmt.Errorf("error decoding TO2.Done request: %w", err)
	}

	// Get session nonces
	proveDeviceNonce, err := s.Nonces.ProveDeviceNonce(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving ProveDevice nonce for session: %w", err)
	}
	setupDeviceNonce, err := s.Nonces.SetupDeviceNonce(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving SetupDevice nonce for session: %w", err)
	}

	// Validate request nonce
	if !bytes.Equal(proveDeviceNonce[:], done.NonceTO2ProveDv[:]) {
		return nil, fmt.Errorf("nonce from TO2.ProveDevice did not match TO2.Done")
	}

	// Get voucher and voucher replacement state
	currentGUID, err := s.Proofs.GUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving associated device GUID of proof session: %w", err)
	}
	currentOV, err := s.Devices.Voucher(ctx, currentGUID)
	if err != nil {
		return nil, fmt.Errorf("error retrieving voucher for device %x: %w", currentGUID, err)
	}
	replacementGUID, err := s.Replacements.ReplacementGUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving replacement GUID for device: %w", err)
	}
	replacementHmac, err := s.Replacements.ReplacementHmac(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving replacement Hmac for device: %w", err)
	}

	// Create and store a new voucher
	keyType := currentOV.Header.Val.ManufacturerKey.Type
	key, ok := s.OwnerKeys.Signer(keyType)
	if !ok {
		return nil, fmt.Errorf("key type %s not supported", keyType)
	}
	ownerPublicKey, err := newPublicKey(keyType, key.Public())
	if err != nil {
		return nil, fmt.Errorf("error with owner public key: %w", err)
	}
	ov := &Voucher{
		Version: currentOV.Version,
		Header: *cbor.NewBstr(VoucherHeader{
			Version:         currentOV.Header.Val.Version,
			GUID:            replacementGUID,
			RvInfo:          s.RvInfo,
			DeviceInfo:      currentOV.Header.Val.DeviceInfo,
			ManufacturerKey: *ownerPublicKey,
			CertChainHash:   currentOV.Header.Val.CertChainHash,
		}),
		Hmac:      replacementHmac,
		CertChain: currentOV.CertChain,
		Entries:   nil,
	}
	if err := s.Devices.ReplaceVoucher(ctx, currentGUID, ov); err != nil {
		return nil, fmt.Errorf("error replacing persisted voucher: %w", err)
	}

	// Respond with nonce
	return &done2Msg{
		NonceTO2SetupDv: setupDeviceNonce,
	}, nil
}
