// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package kex

import (
	"crypto"
	"strconv"

	"github.com/fido-device-onboard/go-fdo/cose"
)

// CipherSuiteID enumeration
type CipherSuiteID int64

// Cipher suite IDs
const (
	// Authenticated encryption ciphers
	A128GcmCipher          CipherSuiteID = 1
	A256GcmCipher          CipherSuiteID = 2
	AesCcm16_128_128Cipher CipherSuiteID = 30 // deprecated, not implemented
	AesCcm16_128_256Cipher CipherSuiteID = 31 // deprecated, not implemented
	AesCcm64_128_128Cipher CipherSuiteID = 32
	AesCcm64_128_256Cipher CipherSuiteID = 33

	// Encrypt-then-MAC ciphers
	CoseAes128CbcCipher CipherSuiteID = -17760703
	CoseAes128CtrCipher CipherSuiteID = -17760704
	CoseAes256CbcCipher CipherSuiteID = -17760705
	CoseAes256CtrCipher CipherSuiteID = -17760706
)

// New returns a new cipher suite registered to the given ID.
func (id CipherSuiteID) New() *CipherSuite {
	f, ok := ciphers[id]
	if !ok {
		panic("cipher suite not registered: " + strconv.Itoa(int(id)))
	}
	return f()
}

// CipherSuite combines a COSE encryption algorithm with a COSE MAC algorithm.
// MacAlg must only be non-zero when EncryptAlg is a non-AE cipher.
type CipherSuite struct {
	EncryptAlg cose.EncryptAlgorithm
	MacAlg     cose.MacAlgorithm

	// Hash used for generating encryption and verification keys during key
	// exchange
	PRFHash crypto.Hash
}

var ciphers = make(map[CipherSuiteID]func() *CipherSuite)

// RegisterCipherSuite sets a new cipher suite constructor for a given ID. This
// function is meant to be called in the init function of a package
// implementing a cipher suite.
func RegisterCipherSuite(id CipherSuiteID, f func() *CipherSuite) { ciphers[id] = f }

// ┌────────────────────────┬──────────────────────────────────────┬─────────────────────────────────────┐
// │Cipher Suite Name       │ Initialization Vector (IVData.iv in  │ Notes                               │
// │(see TO2.HelloDevice)   │ "ct" message header)                 │                                     │
// ├────────────────────────┼──────────────────────────────────────┼─────────────────────────────────────┤
// │ A128GCM                │ Defined as per COSE specification.   │ COSE encryption modes are preferred,│
// │ A256GCM                │ Other COSE encryption modes are also │ where available.                    │
// │ AES-CCM-64-128-128     │ supported.                           │                                     │
// │ AES-CCM-64-128-256     │                                      │ KDF uses HMAC-SHA256                │
// ├────────────────────────┼──────────────────────────────────────┼─────────────────────────────────────┤
// │ AES128/CTR/HMAC-SHA256 │ The IV for AES CTR Mode is 16 bytes  │ This is the preferred encrypt-then- │
// │                        │ long in big-endian byte order, where:│ mac cipher suite for FIDO Device    │
// │                        │                                      │ Onboard for 128-bit keys. Other     │
// │                        │ - The first 12 bytes of IV (nonce)   │ suites are provided for situations  │
// │                        │   are randomly generated at the      │ where Device implementations cannot │
// │                        │   beginning of a session,            │ use this suite. AES in Counter Mode │
// │                        │   independently by both sides.       │ [6] with 128 bit key using the SEK  │
// │                        │ - The last 4 bytes of IV (counter)   │ from key exchange.                  │
// │                        │   is initialized to 0 at the         │                                     │
// │                        │   beginning of the session.          │ KDF uses HMAC-SHA256                │
// │                        │ - The IV value must be maintained    │                                     │
// │                        │   with the current session key.      │                                     │
// │                        │   “Maintain” means that the IV will  │                                     │
// │                        │   be changed by the underlying       │                                     │
// │                        │   encryption mechanism and must be   │                                     │
// │                        │   copied back to the current session │                                     │
// │                        │   state for future encryption.       │                                     │
// │                        │ - For decryption, the IV will come   │                                     │
// │                        │   in the header of the received      │                                     │
// │                        │   message.                           │                                     │
// │                        │                                      │                                     │
// │                        │ The random data source must be a     │                                     │
// │                        │ cryptographically strong pseudo      │                                     │
// │                        │ random number generator (CSPRNG) or  │                                     │
// │                        │ a true random number generator       │                                     │
// │                        │ (TNRG).                              │                                     │
// ├────────────────────────┼──────────────────────────────────────┼─────────────────────────────────────┤
// │ AES128/CBC/HMAC-SHA256 │ IV is 16 bytes containing random     │ AES in Cipher Block Chaining (CBC)  │
// │                        │ data, to use as initialization       │ Mode [3] with PKCS#7 [17] padding.  │
// │                        │ vector for CBC mode. The random      │ The key is the SEK from key         │
// │                        │ data must be freshly generated for   │ exchange.                           │
// │                        │ every encrypted message. The random  │                                     │
// │                        │ data source must be a                │ Implementation notes:               │
// │                        │ cryptographically strong pseudo      │                                     │
// │                        │ random number generator (CSPRNG) or  │ - Implementation may not return an  │
// │                        │ a true random number generator       │   error that indicates a padding    │
// │                        │ (TNRG).                              │   failure.                          │
// │                        │                                      │ - The implementation must only      │
// │                        │                                      │   return the decryption error after │
// │                        │                                      │   the "expected" processing time    │
// │                        │                                      │   for this message.                 │
// │                        │                                      │                                     │
// │                        │                                      │ It is recognized that the first     │
// │                        │                                      │ item is hard to achieve in general, │
// │                        │                                      │ but FIDO Device Onboard risk is low │
// │                        │                                      │ in this area, because any           │
// │                        │                                      │ decryption error will cause the     │
// │                        │                                      │ connection to be torn down.         │
// │                        │                                      │                                     │
// │                        │                                      │ KDF uses HMAC-SHA256                │
// ┼────────────────────────┼──────────────────────────────────────┼─────────────────────────────────────┤
// │ AES256/CTR/HMAC-SHA384 │ The IV for AES CTR Mode is 16 bytes  │ This is the preferred encrypt-then- │
// │                        │ long in big-endian byte order,       │ mac cipher suite for FIDO Device    │
// │                        │ where:                               │ Onboard for 256-bit keys. Other     │
// │                        │                                      │ suites are provided for situations  │
// │                        │ - The first 12 bytes of IV (nonce)   │ where Device implementations cannot │
// │                        │   are randomly generated at the      │ use this suite. AES in Counter Mode │
// │                        │   beginning of a session,            │ [6] with 256 bit key using the SEK  │
// │                        │   independently by both sides.       │ from key exchange.                  │
// │                        │ - The last 4 bytes of IV (counter)   │                                     │
// │                        │   is initialized to 0 at the         │ KDF uses HMAC-SHA384                │
// │                        │   beginning of the session.          │                                     │
// │                        │ - The IV value must be maintained    │                                     │
// │                        │   with the current session key.      │                                     │
// │                        │   “Maintain” means that the IV will  │                                     │
// │                        │   be changed by the underlying       │                                     │
// │                        │   encryption mechanism and must be   │                                     │
// │                        │   copied back to the current         │                                     │
// │                        │   session state for future           │                                     │
// │                        │   encryption.                        │                                     │
// │                        │ - For decryption, the IV will come   │                                     │
// │                        │   in the header of the received      │                                     │
// │                        │   message.                           │                                     │
// │                        │                                      │                                     │
// │                        │ The random data source must be a     │                                     │
// │                        │ cryptographically strong pseudo      │                                     │
// │                        │ random number generator (CSPRNG) or  │                                     │
// │                        │ a true random number generator       │                                     │
// │                        │ (TNRG).                              │                                     │
// ├────────────────────────┼──────────────────────────────────────┼─────────────────────────────────────┤
// │ AES256/CBC/HMAC-SHA384 │ IV is 16 bytes containing random     │ Implementation notes:               │
// │                        │ data, to use as initialization       │                                     │
// │                        │ vector for CBC mode. The random      │ - Implementation may not return an  │
// │                        │ data must be freshly generated for   │   error that indicates a padding    │
// │                        │ every encrypted message. The random  │   failure.                          │
// │                        │ data source must be                  │ - The implementation must only      │
// │                        │ cryptographically strong pseudo      │   return the decryption error after │
// │                        │ random number generator (CSPRNG) or  │   the "expected" processing time    │
// │                        │ a true random number generator       │   for this message.                 │
// │                        │ (TNRG) AES-256 in Cipher Block       │                                     │
// │                        │ Chaining (CBC) Mode [15] with        │ It is recognized that the item is   │
// │                        │ PKCS#7[16] padding. The key is the   │ hard to achieve in general, but     │
// │                        │ SEK from key exchange.               │ FIDO Device Onboard risk is low in  │
// │                        │                                      │ this area, because any decryption   │
// │                        │                                      │ error causes the connection to be   │
// │                        │                                      │ torn down.                          │
// │                        │                                      │                                     │
// │                        │                                      │ KDF uses HMAC-SHA384                │
// └────────────────────────┴──────────────────────────────────────┴─────────────────────────────────────┘
func init() {
	RegisterCipherSuite(A128GcmCipher, func() *CipherSuite {
		return &CipherSuite{
			EncryptAlg: cose.A128GCM,
			PRFHash:    crypto.SHA256,
		}
	})
	RegisterCipherSuite(A256GcmCipher, func() *CipherSuite {
		return &CipherSuite{
			EncryptAlg: cose.A256GCM,
			PRFHash:    crypto.SHA256,
		}
	})
	RegisterCipherSuite(CoseAes128CtrCipher, func() *CipherSuite {
		return &CipherSuite{
			EncryptAlg: -1, // FIXME:
			MacAlg:     cose.HMac256,
			PRFHash:    crypto.SHA256,
		}
	})
	RegisterCipherSuite(CoseAes128CbcCipher, func() *CipherSuite {
		return &CipherSuite{
			EncryptAlg: -1, // FIXME:
			MacAlg:     cose.HMac256,
			PRFHash:    crypto.SHA256,
		}
	})
	RegisterCipherSuite(CoseAes256CtrCipher, func() *CipherSuite {
		return &CipherSuite{
			EncryptAlg: -1, // FIXME:
			MacAlg:     cose.HMac384,
			PRFHash:    crypto.SHA384,
		}
	})
	RegisterCipherSuite(CoseAes256CbcCipher, func() *CipherSuite {
		return &CipherSuite{
			EncryptAlg: -1, // FIXME:
			MacAlg:     cose.HMac384,
			PRFHash:    crypto.SHA384,
		}
	})
}
