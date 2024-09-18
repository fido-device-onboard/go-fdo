// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"iter"
	"math"
	"strings"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/kex"
	"github.com/fido-device-onboard/go-fdo/plugin"
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
		return Nonce{}, nil, nil, fmt.Errorf("bad ownership voucher header from TO2.ProveOVHdr: manufacturer key: %w", err)
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
	ownerPub := ov.Header.Val.ManufacturerKey
	if len(ov.Entries) > 0 {
		ownerPub = ov.Entries[len(ov.Entries)-1].Payload.Val.PublicKey
	}
	expectedOwnerPub, err := ownerPub.Public()
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
//nolint:gocyclo // This is very complex validation that is better understood linearly
func (c *Client) helloDevice(ctx context.Context, baseURL string) (Nonce, *ovhValidationContext, kex.Session, error) {
	// Generate a new nonce
	var proveOVNonce Nonce
	if _, err := rand.Read(proveOVNonce[:]); err != nil {
		return Nonce{}, nil, nil, fmt.Errorf("error generating new nonce for TO2.HelloDevice request: %w", err)
	}

	// Select SigInfo using SHA384 when available
	aSigInfo, err := sigInfoFor(c.Key, c.PSS)
	if err != nil {
		return Nonce{}, nil, nil, fmt.Errorf("error selecting aSigInfo for TO2.HelloDevice request: %w", err)
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
func (s *TO2Server) proveOVHdr(ctx context.Context, msg io.Reader) (*cose.Sign1Tag[ovhProof, []byte], error) { //nolint:gocyclo
	// Parse request
	var rawHello cbor.RawBytes
	if err := cbor.NewDecoder(msg).Decode(&rawHello); err != nil {
		return nil, fmt.Errorf("error decoding TO2.HelloDevice request: %w", err)
	}
	var hello helloDeviceMsg
	if err := cbor.Unmarshal(rawHello, &hello); err != nil {
		return nil, fmt.Errorf("error decoding TO2.HelloDevice request: %w", err)
	}

	// Retrieve voucher
	if err := s.Session.SetGUID(ctx, hello.GUID); err != nil {
		return nil, fmt.Errorf("error associating device GUID to proof session: %w", err)
	}
	ov, err := s.Vouchers.Voucher(ctx, hello.GUID)
	if err != nil {
		captureErr(ctx, resourceNotFound, "")
		return nil, fmt.Errorf("error retrieving voucher for device %x: %w", hello.GUID, err)
	}
	// It is legal for this tag to have a value of zero (0), but this is
	// only useful in re-manufacturing situations, since the Rendezvous
	// Server cannot verify (or accept) these Ownership Proxies.
	numEntries := len(ov.Entries)
	if numEntries > math.MaxUint8 {
		return nil, fmt.Errorf("voucher for device %x has too many entries", hello.GUID)
	}

	// Verify voucher using custom configuration option.
	if s.VerifyVoucher != nil {
		if err := s.VerifyVoucher(ctx, *ov); err != nil {
			captureErr(ctx, resourceNotFound, "")
			return nil, fmt.Errorf("VerifyVoucher: %w", err)
		}
	} else if numEntries == 0 {
		captureErr(ctx, resourceNotFound, "")
		return nil, fmt.Errorf("error retrieving voucher for device %x: %w", hello.GUID, ErrNotFound)
	}

	// Hash request
	helloDeviceHash := Hash{Algorithm: ov.Header.Val.CertChainHash.Algorithm}
	helloDeviceHasher := helloDeviceHash.Algorithm.HashFunc().New()
	_, _ = helloDeviceHasher.Write(rawHello)
	helloDeviceHash.Value = helloDeviceHasher.Sum(nil)

	// Generate nonce for ProveDevice
	var proveDeviceNonce Nonce
	if _, err := rand.Read(proveDeviceNonce[:]); err != nil {
		return nil, fmt.Errorf("error generating new nonce for TO2.ProveOVHdr response: %w", err)
	}
	if err := s.Session.SetProveDeviceNonce(ctx, proveDeviceNonce); err != nil {
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
	if err := s.Session.SetXSession(ctx, hello.KexSuiteName, sess); err != nil {
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
	ownerKey, ownerPublicKey, err := s.ownerKey(keyType, ov.Header.Val.ManufacturerKey.Encoding)
	if err != nil {
		return nil, err
	}
	// Assert that owner key matches voucher, in case the key was replaced or
	// the voucher was not extended before being stored
	expectedCUPHOwnerKey, err := ov.OwnerPublicKey()
	if err != nil {
		return nil, fmt.Errorf("error parsing owner public key from voucher: %w", err)
	}
	if !ownerKey.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(expectedCUPHOwnerKey) {
		return nil, fmt.Errorf("owner key to be used for CUPHOwnerKey does not match voucher")
	}
	s1 := cose.Sign1[ovhProof, []byte]{
		Header: cose.Header{
			Unprotected: map[cose.Label]any{
				to2NonceClaim:       proveDeviceNonce,
				to2OwnerPubKeyClaim: ownerPublicKey,
			},
		},
		Payload: cbor.NewByteWrap(ovhProof{
			OVH:                 ov.Header,
			NumOVEntries:        uint8(numEntries),
			OVHHmac:             ov.Hmac,
			NonceTO2ProveOV:     hello.NonceTO2ProveOV,
			SigInfoB:            hello.SigInfoA,
			KeyExchangeA:        xA,
			HelloDeviceHash:     helloDeviceHash,
			MaxOwnerMessageSize: 65535, // TODO: Make this configurable and match handler config
		}),
	}
	if err := s1.Sign(ownerKey, nil, nil, opts); err != nil {
		return nil, fmt.Errorf("error signing TO2.ProveOVHdr payload: %w", err)
	}

	return s1.Tag(), nil
}

func (s *TO2Server) ownerKey(keyType KeyType, keyEncoding KeyEncoding) (crypto.Signer, *PublicKey, error) {
	key, chain, err := s.OwnerKeys.OwnerKey(keyType)
	if errors.Is(err, ErrNotFound) {
		return nil, nil, fmt.Errorf("owner key type %s not supported", keyType)
	} else if err != nil {
		return nil, nil, fmt.Errorf("error getting owner key [type=%s]: %w", keyType, err)
	}

	pub := key.Public()
	if keyEncoding == X5ChainKeyEnc && len(chain) > 0 {
		pub = chain
	}
	pubkey, err := newPublicKey(keyType, pub, keyEncoding == CoseKeyEnc)
	if err != nil {
		return nil, nil, fmt.Errorf("error with owner public key: %w", err)
	}
	return key, pubkey, nil
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
func (s *TO2Server) ovNextEntry(ctx context.Context, msg io.Reader) (*ovEntry, error) {
	// Parse request
	var nextEntry struct {
		OVEntryNum int
	}
	if err := cbor.NewDecoder(msg).Decode(&nextEntry); err != nil {
		return nil, fmt.Errorf("error decoding TO2.GetOVNextEntry request: %w", err)
	}

	// Retrieve voucher
	guid, err := s.Session.GUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving associated device GUID of proof session: %w", err)
	}
	ov, err := s.Vouchers.Voucher(ctx, guid)
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
	token := cose.Sign1[eatoken, []byte]{
		Header: cose.Header{
			Unprotected: map[cose.Label]any{
				eatUnprotectedNonceClaim: setupDeviceNonce,
			},
		},
		Payload: cbor.NewByteWrap(newEAT(c.Cred.GUID, proveDeviceNonce, struct {
			KeyExchangeB []byte
		}{
			KeyExchangeB: paramB,
		}, nil)),
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
//nolint:gocyclo // This is very complex validation that is better understood linearly
func (s *TO2Server) setupDevice(ctx context.Context, msg io.Reader) (*cose.Sign1Tag[deviceSetup, []byte], error) {
	// Decode a fully-parsed and raw COSE Sign1. The latter is used for
	// verifying in a more lenient way, as it doesn't require deterministic
	// encoding of CBOR (even though FDO requires this).
	var proof cose.Sign1Tag[cbor.RawBytes, []byte]
	if err := cbor.NewDecoder(msg).Decode(&proof); err != nil {
		return nil, fmt.Errorf("error decoding TO2.ProveDevice request: %w", err)
	}
	var eat eatoken
	if err := cbor.Unmarshal([]byte(proof.Payload.Val), &eat); err != nil {
		return nil, fmt.Errorf("error decoding TO2.ProveDevice request: %w", err)
	}

	// Parse and store SetupDevice nonce
	var setupDeviceNonce Nonce
	if ok, err := proof.Unprotected.Parse(eatUnprotectedNonceClaim, &setupDeviceNonce); err != nil {
		return nil, fmt.Errorf("error parsing SetupDevice nonce from TO2.ProveDevice request unprotected header: %w", err)
	} else if !ok {
		return nil, fmt.Errorf("TO2.ProveDevice request missing SetupDevice nonce in unprotected headers")
	}
	if err := s.Session.SetSetupDeviceNonce(ctx, setupDeviceNonce); err != nil {
		return nil, fmt.Errorf("error storing SetupDevice nonce from TO2.ProveDevice request: %w", err)
	}

	// Retrieve voucher
	guid, err := s.Session.GUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving associated device GUID of proof session: %w", err)
	}
	ov, err := s.Vouchers.Voucher(ctx, guid)
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
	proveDeviceNonce, err := s.Session.ProveDeviceNonce(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving ProveDevice nonce for session: %w", err)
	}
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
	suite, sess, err := s.Session.XSession(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting associated key exchange session: %w", err)
	}
	if err := sess.SetParameter(xB); err != nil {
		return nil, fmt.Errorf("error completing key exchange: %w", err)
	}
	if err := s.Session.SetXSession(ctx, suite, sess); err != nil {
		return nil, fmt.Errorf("error updating associated key exchange session: %w", err)
	}

	// Get configured RV info
	rvInfo, err := s.RvInfo(ctx, *ov)
	if err != nil {
		return nil, fmt.Errorf("error determining rendezvous info for device: %w", err)
	}
	if err := s.Session.SetRvInfo(ctx, rvInfo); err != nil {
		return nil, fmt.Errorf("error storing rendezvous info for device: %w", err)
	}

	// Generate a replacement GUID
	var replacementGUID GUID
	if _, err := rand.Read(replacementGUID[:]); err != nil {
		return nil, fmt.Errorf("error generating replacement GUID for device: %w", err)
	}
	if err := s.Session.SetReplacementGUID(ctx, replacementGUID); err != nil {
		return nil, fmt.Errorf("error storing replacement GUID for device: %w", err)
	}

	// Respond with device setup
	keyType := ov.Header.Val.ManufacturerKey.Type
	ownerKey, ownerPublicKey, err := s.ownerKey(keyType, ov.Header.Val.ManufacturerKey.Encoding)
	if err != nil {
		return nil, err
	}
	s1 := cose.Sign1[deviceSetup, []byte]{
		Payload: cbor.NewByteWrap(deviceSetup{
			RendezvousInfo:  rvInfo,
			GUID:            replacementGUID,
			NonceTO2SetupDv: setupDeviceNonce,
			Owner2Key:       *ownerPublicKey,
		}),
	}
	opts, err := signOptsFor(ownerKey, keyType == RsaPssKeyType)
	if err != nil {
		return nil, fmt.Errorf("error determining signing options for TO2.SetupDevice message: %w", err)
	}
	if err := s1.Sign(ownerKey, nil, nil, opts); err != nil {
		return nil, fmt.Errorf("error signing TO2.SetupDevice payload: %w", err)
	}
	return s1.Tag(), nil
}

type deviceServiceInfoReady struct {
	Hmac                    *Hmac
	MaxOwnerServiceInfoSize *uint16 // maximum size service info that Device can receive
}

// DeviceServiceInfoReady(66) -> OwnerServiceInfoReady(67)
func (c *Client) readyServiceInfo(ctx context.Context, baseURL string, alg HashAlg, replacementOVH *VoucherHeader, session kex.Session) (maxDeviceServiceInfoSiz uint16, err error) {
	// Calculate the new OVH HMac similar to DI.SetHMAC
	switch alg {
	case Sha256Hash, HmacSha256Hash:
		alg = HmacSha256Hash
	case Sha384Hash, HmacSha384Hash:
		alg = HmacSha384Hash
	default:
		panic("only SHA256 and SHA384 are supported in FDO")
	}
	replacementHmac, err := hmacHash(c.Hmac, alg, replacementOVH)
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
func (s *TO2Server) ownerServiceInfoReady(ctx context.Context, msg io.Reader) (*ownerServiceInfoReady, error) {
	// Parse request
	var deviceReady deviceServiceInfoReady
	if err := cbor.NewDecoder(msg).Decode(&deviceReady); err != nil {
		return nil, fmt.Errorf("error decoding TO2.DeviceServiceInfoReady request: %w", err)
	}

	// Store new HMAC for voucher replacement
	if deviceReady.Hmac == nil {
		return nil, fmt.Errorf("device did not send a replacement voucher HMAC")
	}
	if err := s.Session.SetReplacementHmac(ctx, *deviceReady.Hmac); err != nil {
		return nil, fmt.Errorf("error storing replacement voucher HMAC for device: %w", err)
	}

	// Set send MTU
	mtu := uint16(serviceinfo.DefaultMTU)
	if deviceReady.MaxOwnerServiceInfoSize != nil {
		mtu = *deviceReady.MaxOwnerServiceInfoSize
	}
	if err := s.Session.SetMTU(ctx, mtu); err != nil {
		return nil, fmt.Errorf("error storing max service info size to send to device: %w", err)
	}

	// Get voucher and voucher replacement state
	currentGUID, err := s.Session.GUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving associated device GUID of proof session: %w", err)
	}
	currentOV, err := s.Vouchers.Voucher(ctx, currentGUID)
	if err != nil {
		return nil, fmt.Errorf("error retrieving voucher for device %x: %w", currentGUID, err)
	}
	replacementGUID, err := s.Session.ReplacementGUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving replacement GUID for device: %w", err)
	}
	info := currentOV.Header.Val.DeviceInfo
	var deviceCertChain []*x509.Certificate
	if currentOV.CertChain != nil {
		deviceCertChain = make([]*x509.Certificate, len(*currentOV.CertChain))
		for i, cert := range *currentOV.CertChain {
			deviceCertChain[i] = (*x509.Certificate)(cert)
		}
	}

	// Initialize service info modules
	s.plugins = nil
	s.nextModule, s.stop = iter.Pull2(func() iter.Seq2[string, serviceinfo.OwnerModule] {
		var devmod devmodOwnerModule
		var ownerModules iter.Seq2[string, serviceinfo.OwnerModule]

		return func(yield func(string, serviceinfo.OwnerModule) bool) {
			if ownerModules == nil {
				if !yield(devmodModuleName, &devmod) {
					return
				}
				ownerModules = s.OwnerModules(ctx, replacementGUID, info, deviceCertChain, devmod.Devmod, devmod.Modules)
			}

			ownerModules(func(moduleName string, mod serviceinfo.OwnerModule) bool {
				if p, ok := mod.(plugin.Module); ok {
					// Collect plugins before yielding the module
					s.plugins = append(s.plugins, p)
				}
				return yield(moduleName, mod)
			})
		}
	}())

	// Send response
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
func (c *Client) exchangeServiceInfo(ctx context.Context,
	baseURL string,
	proveDvNonce, setupDvNonce Nonce,
	mtu uint16,
	initInfo *serviceinfo.ChunkReader,
	deviceModules map[string]serviceinfo.DeviceModule,
	session kex.Session,
) error {
	// Shadow context to ensure that any goroutines still running after this
	// function exits will shutdown
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Subtract 3 bytes from MTU to account for a CBOR header indicating "array
	// of 256-65535 items" and 2 more bytes for "array of two" plus the first
	// item indicating "IsMoreServiceInfo"
	// TODO: Should this only be 3?
	mtu -= 5

	// 1000 service info buffered in and out means up to ~1MB of data for
	// the default MTU. If both queues fill, the device will deadlock. This
	// should only happen for a poorly behaved owner service.
	ownerInfo, ownerInfoIn := serviceinfo.NewChunkInPipe(1000)

	// Send initial device info (devmod)
	totalRounds, done, err := c.exchangeServiceInfoRound(ctx, baseURL, mtu, initInfo, ownerInfoIn, session)
	_ = initInfo.Close()
	if err != nil {
		return fmt.Errorf("error sending devmod: %w", err)
	}
	if err := ownerInfoIn.Close(); err != nil {
		return fmt.Errorf("error closing owner service info -> device module pipe: %w", err)
	}
	if totalRounds >= 1_000_000 {
		return fmt.Errorf("exceeded 1e6 rounds of service info exchange")
	}
	if done {
		return c.done(ctx, baseURL, proveDvNonce, setupDvNonce, session)
	}

	// Track active modules
	modules := deviceModuleMap{modules: deviceModules, active: make(map[string]bool)}

	var prevModuleName string
	for {
		// Handle received owner service info and produce zero or more service
		// info to send. Each service info grouping is automatically chunked
		// and if it exceeds the MTU will have IsMoreServiceInfo=true.
		//
		// 1000 service info buffered in and out means up to ~1MB of data for
		// the default MTU. If both queues fill, the device will deadlock. This
		// should only happen for a poorly behaved owner module.
		deviceInfo, deviceInfoIn := serviceinfo.NewChunkOutPipe(1000)
		ctxWithMTU := context.WithValue(ctx, serviceinfo.MTUKey{}, mtu)
		// Track the owner module in use so that if the next round has no data
		// exchanged, we can still yield to the appropriate device module.
		moduleName := make(chan string)
		go func() {
			select {
			case <-ctx.Done():
			case moduleName <- handleOwnerModuleMessages(ctxWithMTU, prevModuleName, modules, ownerInfo, deviceInfoIn):
			}
		}()

		// Send all device service info and receive all owner service info into
		// a buffered pipe. Note that if >1000 service info are received from
		// the owner service without it allowing the device to respond, the
		// device will deadlock.
		nextOwnerInfo, ownerInfoIn := serviceinfo.NewChunkInPipe(1000)
		rounds, done, err := c.exchangeServiceInfoRound(ctx, baseURL, mtu, deviceInfo, ownerInfoIn, session)
		if err != nil {
			_ = ownerInfoIn.CloseWithError(err)
			return err
		}
		if err := ownerInfoIn.Close(); err != nil {
			return fmt.Errorf("error closing owner service info -> device module pipe: %w", err)
		}

		// Limit to 1e6 (1 million) rounds and fail TO2 if exceeded
		totalRounds += rounds
		if totalRounds >= 1_000_000 {
			return fmt.Errorf("exceeded 1e6 rounds of service info exchange")
		}
		if done {
			break
		}

		// If there is no ServiceInfo to send and the last owner response did
		// not contain any service info, then this is just a regular interval
		// check to see if owner IsDone. In this case, add a delay to avoid
		// clobbering the owner service.
		//
		// TODO: Wait a few seconds if no service info was sent or received in
		// the last round.

		select {
		case <-ctx.Done():
			return ctx.Err()
		case prevModuleName = <-moduleName:
			ownerInfo = nextOwnerInfo
		}
	}

	return c.done(ctx, baseURL, proveDvNonce, setupDvNonce, session)
}

// Done(70) -> Done2(71)
func (c *Client) done(ctx context.Context, baseURL string, proveDvNonce, setupDvNonce Nonce, session kex.Session) error {
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

type deviceServiceInfo struct {
	IsMoreServiceInfo bool
	ServiceInfo       []*serviceinfo.KV
}

func (info deviceServiceInfo) String() string {
	return fmt.Sprintf("More: %t, Info: %v",
		info.IsMoreServiceInfo, info.ServiceInfo)
}

type ownerServiceInfo struct {
	IsMoreServiceInfo bool
	IsDone            bool
	ServiceInfo       []*serviceinfo.KV
}

func (info ownerServiceInfo) String() string {
	return fmt.Sprintf("More: %t, Done: %t, Info: %v",
		info.IsMoreServiceInfo, info.IsDone, info.ServiceInfo)
}

// Perform one iteration of send all device service info (may be across
// multiple FDO messages) and receive all owner service info (same applies).
//
// TODO: Track current round number and stop at 1e6 rather than only checking
// if exceeded after this recursive function completes.
func (c *Client) exchangeServiceInfoRound(ctx context.Context, baseURL string, mtu uint16,
	r *serviceinfo.ChunkReader, w *serviceinfo.ChunkWriter, session kex.Session,
) (int, bool, error) {
	// Create DeviceServiceInfo request structure
	var msg deviceServiceInfo
	maxRead := mtu
	for {
		chunk, err := r.ReadChunk(maxRead)
		if errors.Is(err, io.EOF) {
			break
		}
		if errors.Is(err, serviceinfo.ErrSizeTooSmall) {
			msg.IsMoreServiceInfo = true
			if maxRead == mtu {
				msg.IsMoreServiceInfo = false // likely due to a yield... but also could be a malicious large key?
			}
			break
		}
		if err != nil {
			return 0, false, fmt.Errorf("error reading KV to send to owner: %w", err)
		}
		maxRead -= chunk.Size()
		msg.ServiceInfo = append(msg.ServiceInfo, chunk)
	}

	// Send request
	ownerServiceInfo, err := c.deviceServiceInfo(ctx, baseURL, msg, session)
	if err != nil {
		return 0, false, err
	}

	// Receive all owner service info
	for _, kv := range ownerServiceInfo.ServiceInfo {
		if err := w.WriteChunk(kv); err != nil {
			return 0, false, fmt.Errorf("error piping owner service info to device module: %w", err)
		}
	}

	// Recurse when there's more service info to send from device or receive
	// from owner without allowing the other side to respond
	if msg.IsMoreServiceInfo || ownerServiceInfo.IsMoreServiceInfo {
		rounds, done, err := c.exchangeServiceInfoRound(ctx, baseURL, mtu, r, w, session)
		return rounds + 1, done, err
	}

	return 1, ownerServiceInfo.IsDone, nil
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
func (s *TO2Server) ownerServiceInfo(ctx context.Context, msg io.Reader) (*ownerServiceInfo, error) {
	// Parse request
	var deviceInfo deviceServiceInfo
	if err := cbor.NewDecoder(msg).Decode(&deviceInfo); err != nil {
		return nil, fmt.Errorf("error decoding TO2.DeviceServiceInfo request: %w", err)
	}

	// Get next owner service info module
	moduleName, mod, ok := s.nextModule()
	if !ok {
		return &ownerServiceInfo{
			IsMoreServiceInfo: false,
			IsDone:            true,
			ServiceInfo:       nil,
		}, nil
	}

	// Handle data with owner module
	unchunked, unchunker := serviceinfo.NewChunkInPipe(len(deviceInfo.ServiceInfo))
	for _, kv := range deviceInfo.ServiceInfo {
		if err := unchunker.WriteChunk(kv); err != nil {
			return nil, fmt.Errorf("error unchunking received device service info: write: %w", err)
		}
	}
	if err := unchunker.Close(); err != nil {
		return nil, fmt.Errorf("error unchunking received device service info: close: %w", err)
	}
	for {
		key, messageBody, ok := unchunked.NextServiceInfo()
		if !ok {
			break
		}
		moduleName, messageName, _ := strings.Cut(key, ":")
		if err := mod.HandleInfo(ctx, messageName, messageBody); err != nil {
			return nil, fmt.Errorf("error handling device service info %q: %w", key, err)
		}
		if n, err := io.Copy(io.Discard, messageBody); err != nil {
			return nil, err
		} else if n > 0 {
			return nil, fmt.Errorf(
				"owner module did not read full body of message '%s:%s'",
				moduleName, messageName)
		}
		if err := messageBody.Close(); err != nil {
			return nil, fmt.Errorf("error closing unchunked message body for %q: %w", key, err)
		}
	}

	if deviceInfo.IsMoreServiceInfo {
		s.continueWithModule(moduleName, mod)

		return &ownerServiceInfo{
			IsMoreServiceInfo: false,
			IsDone:            false,
			ServiceInfo:       nil,
		}, nil
	}

	return s.produceOwnerServiceInfo(ctx, moduleName, mod)
}

// Override nextModule so that the same module is used in the next round
func (s *TO2Server) continueWithModule(moduleName string, mod serviceinfo.OwnerModule) {
	nextModule := s.nextModule
	s.nextModule = func() (string, serviceinfo.OwnerModule, bool) {
		s.nextModule = nextModule
		return moduleName, mod, true
	}
}

// Allow owner module to produce data
func (s *TO2Server) produceOwnerServiceInfo(ctx context.Context, moduleName string, mod serviceinfo.OwnerModule) (*ownerServiceInfo, error) {
	mtu, err := s.Session.MTU(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting max device service info size: %w", err)
	}

	producer := serviceinfo.NewProducer(moduleName, mtu)
	explicitBlock, isComplete, err := mod.ProduceInfo(ctx, producer)
	if err != nil {
		return nil, fmt.Errorf("error producing owner service info from module: %w", err)
	}

	if size := serviceinfo.ArraySizeCBOR(producer.ServiceInfo()); size > int64(mtu) {
		return nil, fmt.Errorf("owner service info module produced service info exceeding the MTU=%d - 3 (message overhead), size=%d", mtu, size)
	}

	// If module is not yet complete, override nextModule to return it again
	if !isComplete {
		s.continueWithModule(moduleName, mod)
	}

	// Return chunked data
	return &ownerServiceInfo{
		IsMoreServiceInfo: explicitBlock,
		IsDone:            false,
		ServiceInfo:       producer.ServiceInfo(),
	}, nil
}

// Done(70) -> Done2(71)
func (s *TO2Server) to2Done2(ctx context.Context, msg io.Reader) (*done2Msg, error) {
	// Parse request
	var done doneMsg
	if err := cbor.NewDecoder(msg).Decode(&done); err != nil {
		return nil, fmt.Errorf("error decoding TO2.Done request: %w", err)
	}

	// Get session nonces
	proveDeviceNonce, err := s.Session.ProveDeviceNonce(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving ProveDevice nonce for session: %w", err)
	}
	setupDeviceNonce, err := s.Session.SetupDeviceNonce(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving SetupDevice nonce for session: %w", err)
	}

	// Validate request nonce
	if !bytes.Equal(proveDeviceNonce[:], done.NonceTO2ProveDv[:]) {
		return nil, fmt.Errorf("nonce from TO2.ProveDevice did not match TO2.Done")
	}

	// Get voucher and voucher replacement state
	currentGUID, err := s.Session.GUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving associated device GUID of proof session: %w", err)
	}
	currentOV, err := s.Vouchers.Voucher(ctx, currentGUID)
	if err != nil {
		return nil, fmt.Errorf("error retrieving voucher for device %x: %w", currentGUID, err)
	}

	rvInfo, err := s.Session.RvInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving rendezvous info for device: %w", err)
	}
	replacementGUID, err := s.Session.ReplacementGUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving replacement GUID for device: %w", err)
	}
	replacementHmac, err := s.Session.ReplacementHmac(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving replacement Hmac for device: %w", err)
	}

	// Create and store a new voucher
	keyType := currentOV.Header.Val.ManufacturerKey.Type
	keyEncoding := currentOV.Header.Val.ManufacturerKey.Encoding
	_, ownerPublicKey, err := s.ownerKey(keyType, keyEncoding)
	if err != nil {
		return nil, err
	}
	ov := &Voucher{
		Version: currentOV.Version,
		Header: *cbor.NewBstr(VoucherHeader{
			Version:         currentOV.Header.Val.Version,
			GUID:            replacementGUID,
			RvInfo:          rvInfo,
			DeviceInfo:      currentOV.Header.Val.DeviceInfo,
			ManufacturerKey: *ownerPublicKey,
			CertChainHash:   currentOV.Header.Val.CertChainHash,
		}),
		Hmac:      replacementHmac,
		CertChain: currentOV.CertChain,
		Entries:   nil,
	}
	if err := s.Vouchers.ReplaceVoucher(ctx, currentGUID, ov); err != nil {
		return nil, fmt.Errorf("error replacing persisted voucher: %w", err)
	}

	// Respond with nonce
	return &done2Msg{
		NonceTO2SetupDv: setupDeviceNonce,
	}, nil
}
