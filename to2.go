// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"

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
	nonceClaim       = cose.Label{Int64: 256}
	ownerPubKeyClaim = cose.Label{Int64: 257}
)

// Key exchange suites
//
// When the Owner Key is RSA:
//
//   - “DHKEXid14”:
//     Diffie-Hellman key exchange method using a standard Diffie-Hellman
//     mechanism with a standard NIST exponent and 2048-bit modulus ([RFC3526],
//     id 14). This is the preferred method for RSA2048RESTR Owner keys.
//   - “DHKEXid15”:
//     Diffie-Hellman key exchange method using a standard Diffie-Hellman
//     mechanism with a standard National Institute of Standards and Technology
//     (NIST) exponent and 3072-bit modulus. ([RFC3526], id 15), This is the
//     preferred method for RSA 3072-bit Owner keys.
//   - “ASYMKEX2048”:
//     Asymmetric key exchange method uses the encryption by an Owner key based
//     on RSA2048RESTR; this method is useful in FIDO Device Onboard Client
//     environments where Diffie-Hellman computation is slow or difficult to
//     code.
//   - “ASYMKEX3072”:
//     The Asymmetric key exchange method uses the encryption by an Owner key
//     based on RSA with 3072-bit key.
//
// DHKEXid14 and DHKEXid15 differ in the size of the Diffie-Hellman modulus, which is chosen to match the RSA key size in use.
//
// When the Owner key is ECDSA:
//
//   - “ECDH256”:
//     The ECDH method uses a standard Diffie-Hellman mechanism for ECDSA keys.
//     The ECC keys follow NIST P-256 (SECP256R1)
//   - “ECDH384”:
//     Standard Diffie-Hellman mechanism ECC NIST P-384 (SECP384R1)
type kexSuiteName string

// Key exchange suites
//
// CDDL
//
//	KexSuitNames /= (
//	    "DHKEXid14",
//	    "DHKEXid15",
//	    "ASYMKEX2048",
//	    "ASYMKEX3072",
//	    "ECDH256",
//	    "ECDH384"
//	)
//
//nolint:unused
const (
	kexDHKEXid14   kexSuiteName = "DHKEXid14"
	kexDHKEXid15   kexSuiteName = "DHKEXid15"
	kexASYMKEX2048 kexSuiteName = "ASYMKEX2048"
	kexASYMKEX3072 kexSuiteName = "ASYMKEX3072"
	kexECDH256     kexSuiteName = "ECDH256"
	kexECDH38      kexSuiteName = "ECDH384"
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

// HelloDevice(60) -> ProveOVHdr(61)
// loop[GetOVNextEntry(62) -> OVNextEntry(63)]
func (c *Client) verifyOwner(ctx context.Context) (Nonce, error) {
	type HelloDevice struct {
		MaxDeviceMessageSize uint64
		GUID                 GUID
		NonceTO2ProveOV      Nonce
		KexSuiteName         string
		CipherSuiteName      int64
		ASigInfo             *sigInfo
	}

	panic("unimplemented")
}

// ProveDevice(64) -> SetupDevice(65)
func (c *Client) proveDevice(ctx context.Context, nonce Nonce) (GUID, [][]RvInstruction, PublicKey, error) {
	// TO2ProveOVHdrUnprotectedHeaders is used in TO2.ProveDevice and TO2.Done as
	// COSE signature unprotected headers.
	type TO2ProveOVHdrUnprotectedHeaders struct {
		Nonce          Nonce
		OwnerPublicKey PublicKey
	}

	panic("unimplemented")
}

// DeviceServiceInfoReady(66) -> OwnerServiceInfoReady(67)
// loop[DeviceServiceInfo(68) -> OwnerServiceInfo(69)]
// Done(70) -> Done2(71)
func (c *Client) exchangeServiceInfo(ctx context.Context, replaceHmac Hmac) error {
	panic("unimplemented")
}
