// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
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

// Cipher suites
//
// 	┌────────────────────────┬──────────────────────────────────────┬─────────────────────────────────────┐
// 	│Cipher Suite Name       │ Initialization Vector (IVData.iv in  │ Notes                               │
// 	│(see TO2.HelloDevice)   │ "ct" message header)                 │                                     │
// 	├────────────────────────┼──────────────────────────────────────┼─────────────────────────────────────┤
// 	│ A128GCM                │ Defined as per COSE specification.   │ COSE encryption modes are preferred,│
// 	│ A256GCM                │ Other COSE encryption modes are also │ where available.                    │
// 	│ AES-CCM-64-128-128     │ supported.                           │                                     │
// 	│ AES-CCM-64-128-256     │                                      │ KDF uses HMAC-SHA256                │
// 	├────────────────────────┼──────────────────────────────────────┼─────────────────────────────────────┤
// 	│ AES128/CTR/HMAC-SHA256 │ The IV for AES CTR Mode is 16 bytes  │ This is the preferred encrypt-then- │
// 	│                        │ long in big-endian byte order, where:│ mac cipher suite for FIDO Device    │
// 	│                        │                                      │ Onboard for 128-bit keys. Other     │
// 	│                        │ - The first 12 bytes of IV (nonce)   │ suites are provided for situations  │
// 	│                        │   are randomly generated at the      │ where Device implementations cannot │
// 	│                        │   beginning of a session,            │ use this suite. AES in Counter Mode │
// 	│                        │   independently by both sides.       │ [6] with 128 bit key using the SEK  │
// 	│                        │ - The last 4 bytes of IV (counter)   │ from key exchange.                  │
// 	│                        │   is initialized to 0 at the         │                                     │
// 	│                        │   beginning of the session.          │ KDF uses HMAC-SHA256                │
// 	│                        │ - The IV value must be maintained    │                                     │
// 	│                        │   with the current session key.      │                                     │
// 	│                        │   “Maintain” means that the IV will  │                                     │
// 	│                        │   be changed by the underlying       │                                     │
// 	│                        │   encryption mechanism and must be   │                                     │
// 	│                        │   copied back to the current session │                                     │
// 	│                        │   state for future encryption.       │                                     │
// 	│                        │ - For decryption, the IV will come   │                                     │
// 	│                        │   in the header of the received      │                                     │
// 	│                        │   message.                           │                                     │
// 	│                        │                                      │                                     │
// 	│                        │ The random data source must be a     │                                     │
// 	│                        │ cryptographically strong pseudo      │                                     │
// 	│                        │ random number generator (CSPRNG) or  │                                     │
// 	│                        │ a true random number generator       │                                     │
// 	│                        │ (TNRG).                              │                                     │
// 	├────────────────────────┼──────────────────────────────────────┼─────────────────────────────────────┤
// 	│ AES128/CBC/HMAC-SHA256 │ IV is 16 bytes containing random     │ AES in Cipher Block Chaining (CBC)  │
// 	│                        │ data, to use as initialization       │ Mode [3] with PKCS#7 [17] padding.  │
// 	│                        │ vector for CBC mode. The random      │ The key is the SEK from key         │
// 	│                        │ data must be freshly generated for   │ exchange.                           │
// 	│                        │ every encrypted message. The random  │                                     │
// 	│                        │ data source must be a                │ Implementation notes:               │
// 	│                        │ cryptographically strong pseudo      │                                     │
// 	│                        │ random number generator (CSPRNG) or  │ - Implementation may not return an  │
// 	│                        │ a true random number generator       │   error that indicates a padding    │
// 	│                        │ (TNRG).                              │   failure.                          │
// 	│                        │                                      │ - The implementation must only      │
// 	│                        │                                      │   return the decryption error after │
// 	│                        │                                      │   the "expected" processing time    │
// 	│                        │                                      │   for this message.                 │
// 	│                        │                                      │                                     │
// 	│                        │                                      │ It is recognized that the first     │
// 	│                        │                                      │ item is hard to achieve in general, │
// 	│                        │                                      │ but FIDO Device Onboard risk is low │
// 	│                        │                                      │ in this area, because any           │
// 	│                        │                                      │ decryption error will cause the     │
// 	│                        │                                      │ connection to be torn down.         │
// 	│                        │                                      │                                     │
// 	│                        │                                      │ KDF uses HMAC-SHA256                │
// 	┼────────────────────────┼──────────────────────────────────────┼─────────────────────────────────────┤
// 	│ AES256/CTR/HMAC-SHA384 │ The IV for AES CTR Mode is 16 bytes  │ This is the preferred encrypt-then- │
// 	│                        │ long in big-endian byte order,       │ mac cipher suite for FIDO Device    │
// 	│                        │ where:                               │ Onboard for 256-bit keys. Other     │
// 	│                        │                                      │ suites are provided for situations  │
// 	│                        │ - The first 12 bytes of IV (nonce)   │ where Device implementations cannot │
// 	│                        │   are randomly generated at the      │ use this suite. AES in Counter Mode │
// 	│                        │   beginning of a session,            │ [6] with 256 bit key using the SEK  │
// 	│                        │   independently by both sides.       │ from key exchange.                  │
// 	│                        │ - The last 4 bytes of IV (counter)   │                                     │
// 	│                        │   is initialized to 0 at the         │ KDF uses HMAC-SHA384                │
// 	│                        │   beginning of the session.          │                                     │
// 	│                        │ - The IV value must be maintained    │                                     │
// 	│                        │   with the current session key.      │                                     │
// 	│                        │   “Maintain” means that the IV will  │                                     │
// 	│                        │   be changed by the underlying       │                                     │
// 	│                        │   encryption mechanism and must be   │                                     │
// 	│                        │   copied back to the current         │                                     │
// 	│                        │   session state for future           │                                     │
// 	│                        │   encryption.                        │                                     │
// 	│                        │ - For decryption, the IV will come   │                                     │
// 	│                        │   in the header of the received      │                                     │
// 	│                        │   message.                           │                                     │
// 	│                        │                                      │                                     │
// 	│                        │ The random data source must be a     │                                     │
// 	│                        │ cryptographically strong pseudo      │                                     │
// 	│                        │ random number generator (CSPRNG) or  │                                     │
// 	│                        │ a true random number generator       │                                     │
// 	│                        │ (TNRG).                              │                                     │
// 	├────────────────────────┼──────────────────────────────────────┼─────────────────────────────────────┤
// 	│ AES256/CBC/HMAC-SHA384 │ IV is 16 bytes containing random     │ Implementation notes:               │
// 	│                        │ data, to use as initialization       │                                     │
// 	│                        │ vector for CBC mode. The random      │ - Implementation may not return an  │
// 	│                        │ data must be freshly generated for   │   error that indicates a padding    │
// 	│                        │ every encrypted message. The random  │   failure.                          │
// 	│                        │ data source must be                  │ - The implementation must only      │
// 	│                        │ cryptographically strong pseudo      │   return the decryption error after │
// 	│                        │ random number generator (CSPRNG) or  │   the "expected" processing time    │
// 	│                        │ a true random number generator       │   for this message.                 │
// 	│                        │ (TNRG)	AES-256 in Cipher Block     │                                     │
// 	│                        │ Chaining (CBC) Mode [15] with        │ It is recognized that the item is   │
// 	│                        │ PKCS#7[16] padding. The key is the   │ hard to achieve in general, but     │
// 	│                        │ SEK from key exchange.               │ FIDO Device Onboard risk is low in  │
// 	│                        │                                      │ this area, because any decryption   │
// 	│                        │                                      │ error causes the connection to be   │
// 	│                        │                                      │ torn down.                          │
// 	│                        │                                      │                                     │
// 	│                        │                                      │ KDF uses HMAC-SHA384                │
// 	└────────────────────────┴──────────────────────────────────────┴─────────────────────────────────────┘

// Verify owner by sending HelloDevice and validating the response, as well as
// all ownership voucher entries, which are retrieved iteratively with
// subsequence requests.
func (c *Client) verifyOwner(ctx context.Context, baseURL string, ovhHmac Hmac) (Nonce, error) {
	info, err := c.helloDevice(ctx, baseURL)
	if err != nil {
		return Nonce{}, err
	}

	// Validate OV header HMAC
	if err := hmacVerify(c.Hmac, ovhHmac, info.OVH); err != nil {
		return Nonce{}, fmt.Errorf("bad ownership voucher header from TO2.ProveOVHdr: %w", err)
	}

	// loop[GetOVNextEntry(62) -> OVNextEntry(63)]
	var entries []cose.Sign1Tag[VoucherEntryPayload]
	for i := 0; i < info.NumVoucherEntries; i++ {
		entry, err := c.nextOVEntry(ctx, baseURL, i)
		if err != nil {
			return Nonce{}, err
		}
		entries = append(entries, *entry)
	}

	// TODO: Verify OVEntry list and ensure it ends with given owner key

	return info.ProveDeviceNonce, nil
}

type ownerInfo struct {
	// From ProveOVHdr headers
	ProveDeviceNonce Nonce
	PublicKey        PublicKey

	// From ProveOVHdr body
	OVH                 VoucherHeader
	NumVoucherEntries   int
	SigType             cose.SignatureAlgorithm
	KexSuiteName        kexSuiteName
	KeyExchangeA        []byte
	MaxOwnerMessageSize uint64
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
		CipherSuiteName      cipherSuite
		SigInfoA             sigInfo
	}{
		MaxDeviceMessageSize: 0, // Default size
		GUID:                 c.GUID,
		NonceTO2ProveOV:      helloNonce,
		KexSuiteName:         "",                           // TODO: How to decide?
		CipherSuiteName:      0,                            // TODO: How to decide?
		SigInfoA:             sigInfo{Type: cose.ES384Alg}, // TODO: How to decide?
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
		NumVoucherEntries:   int(proveOVHdr.Payload.Val.NumOVEntries),
		SigType:             proveOVHdr.Payload.Val.SigInfoB.Type,
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
		OVEntryNum: 1,
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
func (c *Client) proveDevice(ctx context.Context, baseURL string, nonce Nonce) (GUID, [][]RvInstruction, PublicKey, error) {
	// TO2ProveOVHdrUnprotectedHeaders is used in TO2.ProveDevice and TO2.Done as
	// COSE signature unprotected headers.
	// type TO2ProveOVHdrUnprotectedHeaders struct {
	// 	Nonce          Nonce
	// 	OwnerPublicKey PublicKey
	// }

	panic("unimplemented")
}

// DeviceServiceInfoReady(66) -> OwnerServiceInfoReady(67)
// loop[DeviceServiceInfo(68) -> OwnerServiceInfo(69)]
// Done(70) -> Done2(71)
func (c *Client) exchangeServiceInfo(ctx context.Context, baseURL string, replaceHmac Hmac, serviceInfos []ServiceInfo) error {
	panic("unimplemented")
}
