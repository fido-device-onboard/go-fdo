// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"crypto"
	"crypto/rand"
	"fmt"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
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

type ownerInfo struct {
	// From ProveOVHdr headers
	ProveDeviceNonce Nonce
	PublicKey        PublicKey

	// From ProveOVHdr body
	OVH               VoucherHeader
	OVHHmac           Hmac
	NumVoucherEntries int

	SigInfo      sigInfo
	KexSuiteName kexSuiteName
	KeyExchangeA []byte

	MaxOwnerMessageSize uint64
}

// Verify owner by sending HelloDevice and validating the response, as well as
// all ownership voucher entries, which are retrieved iteratively with
// subsequence requests.
func (c *Client) verifyOwner(ctx context.Context, baseURL string) (*ownerInfo, error) {
	// Construct ownership voucher from parts received from the owner service
	info, err := c.helloDevice(ctx, baseURL)
	if err != nil {
		return nil, err
	}
	if info.NumVoucherEntries == 0 {
		return nil, fmt.Errorf("ownership voucher cannot have zero entries")
	}
	var entries []cose.Sign1Tag[VoucherEntryPayload]
	for i := 0; i < info.NumVoucherEntries; i++ {
		entry, err := c.nextOVEntry(ctx, baseURL, i)
		if err != nil {
			return nil, err
		}
		entries = append(entries, *entry)
	}
	ov := Voucher{
		Header:  cbor.NewBstr(info.OVH),
		Hmac:    info.OVHHmac,
		Entries: entries,
	}

	// Verify ownership voucher header
	if err := ov.VerifyHeader(c.Hmac); err != nil {
		return nil, fmt.Errorf("bad ownership voucher header from TO2.ProveOVHdr: %w", err)
	}

	// Verify that the owner service corresponds to the most recent device
	// initialization performed by checking that the voucher header has a GUID
	// and/or manufacturer key corresponding to the stored device credentials.
	if err := ov.VerifyManufacturerKey(c.Cred.PublicKeyHash); err != nil {
		return nil, fmt.Errorf("bad ownership voucher header from TO2.ProveOVHdr: %w", err)
	}

	// Verify each entry in the voucher's list by performing iterative
	// signature and hash (header and GUID/devInfo) checks.
	if err := ov.VerifyEntries(); err != nil {
		return nil, fmt.Errorf("bad ownership voucher entries from TO2.ProveOVHdr: %w", err)
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
		return nil, fmt.Errorf("error parsing last public key of ownership voucher: %w", err)
	}
	ownerPub, err := info.PublicKey.Public()
	if err != nil {
		return nil, fmt.Errorf("error parsing public key of owner service: %w", err)
	}
	if !ownerPub.(interface{ Equal(crypto.PublicKey) bool }).Equal(expectedOwnerPub) {
		return nil, fmt.Errorf("owner public key did not match last entry in ownership voucher")
	}

	return info, nil
}

// HelloDevice(60) -> ProveOVHdr(61)
func (c *Client) helloDevice(ctx context.Context, baseURL string) (*ownerInfo, error) {
	// Generate a new nonce
	var helloNonce Nonce
	if _, err := rand.Read(helloNonce[:]); err != nil {
		return nil, fmt.Errorf("error generating new nonce for TO2.HelloDevice request: %w", err)
	}

	// Create a request structure
	helloDeviceMsg := struct {
		MaxDeviceMessageSize uint64
		GUID                 GUID
		NonceTO2ProveOV      Nonce
		KexSuiteName         kexSuiteName
		CipherSuite          cipherSuite
		SigInfoA             sigInfo
	}{
		MaxDeviceMessageSize: 0, // Default size
		GUID:                 c.Cred.GUID,
		NonceTO2ProveOV:      helloNonce,

		// TODO: How to decide? Strongest available
		KexSuiteName: "",

		// TODO: Use strongest available. Always use GCM-256. Double check no
		// TPM issues.
		CipherSuite: 0,

		// TODO: Use strongest available. Check c.Hmac.Supports?
		SigInfoA: sigInfo{Type: cose.ES384Alg},
	}

	// Make a request
	typ, resp, err := c.Transport.Send(ctx, baseURL, to2HelloDeviceMsgType, helloDeviceMsg)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	var proveOVHdr cose.Sign1Tag[struct {
		OVH                 cbor.Bstr[VoucherHeader]
		NumOVEntries        uint8
		OVHHmac             Hmac
		NonceTO2ProveOV     Nonce
		SigInfoB            sigInfo
		KeyExchangeA        []byte
		HelloDeviceHash     Hash
		MaxOwnerMessageSize uint64
	}]
	switch typ {
	case to2ProveOVHdrMsgType:
		if err := cbor.NewDecoder(resp).Decode(&proveOVHdr); err != nil {
			return nil, fmt.Errorf("error parsing TO2.ProveOVHdr contents: %w", err)
		}

	case ErrorMsgType:
		var errMsg ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return nil, fmt.Errorf("error parsing error message contents of TO2.HelloDevice response: %w", err)
		}
		return nil, fmt.Errorf("error received from TO2.HelloDevice request: %w", errMsg)

	default:
		return nil, fmt.Errorf("unexpected message type for response to TO2.HelloDevice: %d", typ)
	}

	// Parse nonce
	var cuphNonce Nonce
	if cuphNonceBytes := []byte(proveOVHdr.Unprotected[to2NonceClaim]); len(cuphNonceBytes) == 0 {
		return nil, fmt.Errorf("nonce unprotected header missing from TO2.ProveOVHdr response message")
	} else if err := cbor.Unmarshal(cuphNonceBytes, &cuphNonce); err != nil {
		return nil, fmt.Errorf("nonce unprotected header from TO2.ProveOVHdr could not be unmarshaled: %w", err)
	}

	// Parse owner public key
	var ownerPubKey PublicKey
	if ownerPubKeyBytes := []byte(proveOVHdr.Unprotected[to2OwnerPubKeyClaim]); len(ownerPubKeyBytes) == 0 {
		return nil, fmt.Errorf("owner pubkey unprotected header missing from TO2.ProveOVHdr response message")
	} else if err := cbor.Unmarshal(ownerPubKeyBytes, &ownerPubKey); err != nil {
		return nil, fmt.Errorf("owner pubkey unprotected header from TO2.ProveOVHdr could not be unmarshaled: %w", err)
	}

	// Validate response signature and nonce. While the payload signature
	// verification is performed using the untrusted owner public key from the
	// headers, this is acceptable, because the owner public key will be
	// subsequently verified when the voucher entry chain is built and
	// verified.
	key, err := ownerPubKey.Public()
	if err != nil {
		return nil, fmt.Errorf("error parsing owner public key to verify TO2.ProveOVHdr payload signature: %w", err)
	}
	if ok, err := proveOVHdr.Verify(key, nil); err != nil {
		return nil, fmt.Errorf("error verifying TO2.ProveOVHdr payload signature: %w", err)
	} else if !ok {
		return nil, fmt.Errorf("%w: TO2.ProveOVHdr payload signature verification failed", ErrCryptoVerifyFailed)
	}
	if proveOVHdr.Payload.Val.NonceTO2ProveOV != helloNonce {
		return nil, fmt.Errorf("nonce in TO2.ProveOVHdr did not match nonce in TO2.HelloDevice")
	}

	return &ownerInfo{
		ProveDeviceNonce: cuphNonce,
		PublicKey:        ownerPubKey,

		OVH:                 proveOVHdr.Payload.Val.OVH.Val,
		OVHHmac:             proveOVHdr.Payload.Val.OVHHmac,
		NumVoucherEntries:   int(proveOVHdr.Payload.Val.NumOVEntries),
		SigInfo:             proveOVHdr.Payload.Val.SigInfoB,
		KexSuiteName:        helloDeviceMsg.KexSuiteName,
		KeyExchangeA:        proveOVHdr.Payload.Val.KeyExchangeA,
		MaxOwnerMessageSize: proveOVHdr.Payload.Val.MaxOwnerMessageSize,
	}, nil
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
	typ, resp, err := c.Transport.Send(ctx, baseURL, to2GetOVNextEntryMsgType, msg)
	if err != nil {
		return nil, fmt.Errorf("error sending TO2.GetOVNextEntry: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	switch typ {
	case to2OVNextEntryMsgType:
		var ovNextEntry struct {
			OVEntryNum int
			OVEntry    cose.Sign1Tag[VoucherEntryPayload]
		}
		if err := cbor.NewDecoder(resp).Decode(&ovNextEntry); err != nil {
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
		return nil, fmt.Errorf("unexpected message type for response to TO2.GetOVNextEntry: %d", typ)
	}
}

// ProveDevice(64) -> SetupDevice(65)
func (c *Client) proveDevice(ctx context.Context, baseURL string, info *ownerInfo) (*VoucherHeader, error) {
	// TO2ProveOVHdrUnprotectedHeaders is used in TO2.ProveDevice and TO2.Done as
	// COSE signature unprotected headers.
	// type TO2ProveOVHdrUnprotectedHeaders struct {
	// 	Nonce          Nonce
	// 	OwnerPublicKey PublicKey
	// }

	panic("unimplemented")
}

// DeviceServiceInfoReady(66) -> OwnerServiceInfoReady(67)
func (c *Client) readyServiceInfo(ctx context.Context, baseURL string, replacementOVH *VoucherHeader) (err error) {
	// TODO: Track max service info size for chunking

	// Calculate the new OVH HMac similar to DI.SetHMAC
	var replacementHmac Hmac
	if c.Hmac.Supports(HmacSha384Hash) {
		replacementHmac, err = c.Hmac.Hmac(HmacSha384Hash, replacementOVH)
	} else {
		replacementHmac, err = c.Hmac.Hmac(HmacSha256Hash, replacementOVH)
	}
	if err != nil {
		return fmt.Errorf("error computing HMAC of ownership voucher header: %w", err)
	}

	// Define request structure
	var msg struct {
		Hmac                    Hmac
		MaxOwnerServiceInfoSize uint16
	}
	msg.Hmac = replacementHmac

	// Make request
	typ, resp, err := c.Transport.Send(ctx, baseURL, to2DeviceServiceInfoReadyMsgType, msg)
	if err != nil {
		return fmt.Errorf("error sending TO2.DeviceServiceInfoReady: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	switch typ {
	case to2OwnerServiceInfoReadyMsgType:
		var ownerServiceInfoReady struct {
			MaxOwnerServiceInfoSize uint16
		}
		if err := cbor.NewDecoder(resp).Decode(&ownerServiceInfoReady); err != nil {
			return fmt.Errorf("error parsing TO2.OwnerServiceInfoReady contents: %w", err)
		}
		return nil

	case ErrorMsgType:
		var errMsg ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return fmt.Errorf("error parsing error message contents of TO2.OwnerServiceInfoReady response: %w", err)
		}
		return fmt.Errorf("error received from TO2.DeviceServiceInfoReady request: %w", errMsg)

	default:
		return fmt.Errorf("unexpected message type for response to TO2.DeviceServiceInfoReady: %d", typ)
	}
}

// loop[DeviceServiceInfo(68) -> OwnerServiceInfo(69)]
// Done(70) -> Done2(71)
func (c *Client) exchangeServiceInfo(ctx context.Context, baseURL string, serviceInfo []ServiceInfo, fsims map[string]ServiceInfoModule) error {
	// TODO: Ensure that provided service info is chunked at correct MTU
	// TODO: Use encryption context

	/*
		sendInfo := make(chan ServiceInfo, len(serviceInfo))
		for _, info := range serviceInfo {
			sendInfo <- info
		}

		recvInfo := make(chan ServiceInfo)
		defer close(recvInfo)

		go func() {
			for info := range recvInfo {
				fsim, ok := fsims[info.Key]
				if !ok {
					// TODO: Log missing FSIM
					continue
				}
				moreInfo := fsim.HandleFSIM(info.Key, []byte(info.Val.Val))
				for _, nextInfo := range moreInfo {
					select {
					case <-ctx.Done():
						return
					case sendInfo <- nextInfo:
					}
				}
			}
		}()
	*/

	// TODO: After all service info has been sent, if the owner service has not
	// returned a service info with IsDone=true, send empty service info at a
	// regular interval with IsMoreServiceInfo=false and wait until owner is
	// done before moving on to sending TO2.Done.

	panic("unimplemented")
}
