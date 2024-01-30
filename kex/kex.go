// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package kex implements the Key Exchange subprotocol of FDO.
package kex

import (
	"io"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// CipherSuite enumeration
//
//	┌────────────────────────┬──────────────────────────────────────┬─────────────────────────────────────┐
//	│Cipher Suite Name       │ Initialization Vector (IVData.iv in  │ Notes                               │
//	│(see TO2.HelloDevice)   │ "ct" message header)                 │                                     │
//	├────────────────────────┼──────────────────────────────────────┼─────────────────────────────────────┤
//	│ A128GCM                │ Defined as per COSE specification.   │ COSE encryption modes are preferred,│
//	│ A256GCM                │ Other COSE encryption modes are also │ where available.                    │
//	│ AES-CCM-64-128-128     │ supported.                           │                                     │
//	│ AES-CCM-64-128-256     │                                      │ KDF uses HMAC-SHA256                │
//	├────────────────────────┼──────────────────────────────────────┼─────────────────────────────────────┤
//	│ AES128/CTR/HMAC-SHA256 │ The IV for AES CTR Mode is 16 bytes  │ This is the preferred encrypt-then- │
//	│                        │ long in big-endian byte order, where:│ mac cipher suite for FIDO Device    │
//	│                        │                                      │ Onboard for 128-bit keys. Other     │
//	│                        │ - The first 12 bytes of IV (nonce)   │ suites are provided for situations  │
//	│                        │   are randomly generated at the      │ where Device implementations cannot │
//	│                        │   beginning of a session,            │ use this suite. AES in Counter Mode │
//	│                        │   independently by both sides.       │ [6] with 128 bit key using the SEK  │
//	│                        │ - The last 4 bytes of IV (counter)   │ from key exchange.                  │
//	│                        │   is initialized to 0 at the         │                                     │
//	│                        │   beginning of the session.          │ KDF uses HMAC-SHA256                │
//	│                        │ - The IV value must be maintained    │                                     │
//	│                        │   with the current session key.      │                                     │
//	│                        │   “Maintain” means that the IV will  │                                     │
//	│                        │   be changed by the underlying       │                                     │
//	│                        │   encryption mechanism and must be   │                                     │
//	│                        │   copied back to the current session │                                     │
//	│                        │   state for future encryption.       │                                     │
//	│                        │ - For decryption, the IV will come   │                                     │
//	│                        │   in the header of the received      │                                     │
//	│                        │   message.                           │                                     │
//	│                        │                                      │                                     │
//	│                        │ The random data source must be a     │                                     │
//	│                        │ cryptographically strong pseudo      │                                     │
//	│                        │ random number generator (CSPRNG) or  │                                     │
//	│                        │ a true random number generator       │                                     │
//	│                        │ (TNRG).                              │                                     │
//	├────────────────────────┼──────────────────────────────────────┼─────────────────────────────────────┤
//	│ AES128/CBC/HMAC-SHA256 │ IV is 16 bytes containing random     │ AES in Cipher Block Chaining (CBC)  │
//	│                        │ data, to use as initialization       │ Mode [3] with PKCS#7 [17] padding.  │
//	│                        │ vector for CBC mode. The random      │ The key is the SEK from key         │
//	│                        │ data must be freshly generated for   │ exchange.                           │
//	│                        │ every encrypted message. The random  │                                     │
//	│                        │ data source must be a                │ Implementation notes:               │
//	│                        │ cryptographically strong pseudo      │                                     │
//	│                        │ random number generator (CSPRNG) or  │ - Implementation may not return an  │
//	│                        │ a true random number generator       │   error that indicates a padding    │
//	│                        │ (TNRG).                              │   failure.                          │
//	│                        │                                      │ - The implementation must only      │
//	│                        │                                      │   return the decryption error after │
//	│                        │                                      │   the "expected" processing time    │
//	│                        │                                      │   for this message.                 │
//	│                        │                                      │                                     │
//	│                        │                                      │ It is recognized that the first     │
//	│                        │                                      │ item is hard to achieve in general, │
//	│                        │                                      │ but FIDO Device Onboard risk is low │
//	│                        │                                      │ in this area, because any           │
//	│                        │                                      │ decryption error will cause the     │
//	│                        │                                      │ connection to be torn down.         │
//	│                        │                                      │                                     │
//	│                        │                                      │ KDF uses HMAC-SHA256                │
//	┼────────────────────────┼──────────────────────────────────────┼─────────────────────────────────────┤
//	│ AES256/CTR/HMAC-SHA384 │ The IV for AES CTR Mode is 16 bytes  │ This is the preferred encrypt-then- │
//	│                        │ long in big-endian byte order,       │ mac cipher suite for FIDO Device    │
//	│                        │ where:                               │ Onboard for 256-bit keys. Other     │
//	│                        │                                      │ suites are provided for situations  │
//	│                        │ - The first 12 bytes of IV (nonce)   │ where Device implementations cannot │
//	│                        │   are randomly generated at the      │ use this suite. AES in Counter Mode │
//	│                        │   beginning of a session,            │ [6] with 256 bit key using the SEK  │
//	│                        │   independently by both sides.       │ from key exchange.                  │
//	│                        │ - The last 4 bytes of IV (counter)   │                                     │
//	│                        │   is initialized to 0 at the         │ KDF uses HMAC-SHA384                │
//	│                        │   beginning of the session.          │                                     │
//	│                        │ - The IV value must be maintained    │                                     │
//	│                        │   with the current session key.      │                                     │
//	│                        │   “Maintain” means that the IV will  │                                     │
//	│                        │   be changed by the underlying       │                                     │
//	│                        │   encryption mechanism and must be   │                                     │
//	│                        │   copied back to the current         │                                     │
//	│                        │   session state for future           │                                     │
//	│                        │   encryption.                        │                                     │
//	│                        │ - For decryption, the IV will come   │                                     │
//	│                        │   in the header of the received      │                                     │
//	│                        │   message.                           │                                     │
//	│                        │                                      │                                     │
//	│                        │ The random data source must be a     │                                     │
//	│                        │ cryptographically strong pseudo      │                                     │
//	│                        │ random number generator (CSPRNG) or  │                                     │
//	│                        │ a true random number generator       │                                     │
//	│                        │ (TNRG).                              │                                     │
//	├────────────────────────┼──────────────────────────────────────┼─────────────────────────────────────┤
//	│ AES256/CBC/HMAC-SHA384 │ IV is 16 bytes containing random     │ Implementation notes:               │
//	│                        │ data, to use as initialization       │                                     │
//	│                        │ vector for CBC mode. The random      │ - Implementation may not return an  │
//	│                        │ data must be freshly generated for   │   error that indicates a padding    │
//	│                        │ every encrypted message. The random  │   failure.                          │
//	│                        │ data source must be                  │ - The implementation must only      │
//	│                        │ cryptographically strong pseudo      │   return the decryption error after │
//	│                        │ random number generator (CSPRNG) or  │   the "expected" processing time    │
//	│                        │ a true random number generator       │   for this message.                 │
//	│                        │ (TNRG)	AES-256 in Cipher Block     │                                     │
//	│                        │ Chaining (CBC) Mode [15] with        │ It is recognized that the item is   │
//	│                        │ PKCS#7[16] padding. The key is the   │ hard to achieve in general, but     │
//	│                        │ SEK from key exchange.               │ FIDO Device Onboard risk is low in  │
//	│                        │                                      │ this area, because any decryption   │
//	│                        │                                      │ error causes the connection to be   │
//	│                        │                                      │ torn down.                          │
//	│                        │                                      │                                     │
//	│                        │                                      │ KDF uses HMAC-SHA384                │
//	└────────────────────────┴──────────────────────────────────────┴─────────────────────────────────────┘
type CipherSuite int64

// Cipher suite values
const (
	A128GcmCipher          CipherSuite = 1
	A256GcmCipher          CipherSuite = 2
	AesCcm16_128_128Cipher CipherSuite = 30
	AesCcm16_128_256Cipher CipherSuite = 31
	AesCcm64_128_128Cipher CipherSuite = 32
	AesCcm64_128_256Cipher CipherSuite = 33
	CoseAes128CbcCipher    CipherSuite = -17760703
	CoseAes128CtrCipher    CipherSuite = -17760704
	CoseAes256CbcCipher    CipherSuite = -17760705
	CoseAes256CtrCipher    CipherSuite = -17760706
)

// Suite name of each key exchange suite
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
type Suite string

// Key exchange suites
//
// CDDL
//
//	KexSuiteNames /= (
//	    "DHKEXid14",
//	    "DHKEXid15",
//	    "ASYMKEX2048",
//	    "ASYMKEX3072",
//	    "ECDH256",
//	    "ECDH384"
//	)
const (
	DHKEXid14Suite   Suite = "DHKEXid14"
	DHKEXid15Suite   Suite = "DHKEXid15"
	ASYMKEX2048Suite Suite = "ASYMKEX2048"
	ASYMKEX3072Suite Suite = "ASYMKEX3072"
	ECDH256Suite     Suite = "ECDH256"
	ECDH384Suite     Suite = "ECDH384"
)

var constructors = make(map[string]func([]byte, CipherSuite) Session)

// RegisterNewSuite sets a constructor for a Session using a given key
// exchange suite.
func RegisterNewSuite(name string, f func([]byte, CipherSuite) Session) { constructors[name] = f }

// New returns a Session for the given key exchange suite. If no session
// constructor is registered for the suite, then the return value is nil.
func (s Suite) New(xA []byte, c CipherSuite) Session {
	f := constructors[string(s)]
	if f == nil {
		return nil
	}
	return f(xA, c)
}

// Session implements encryption/decryption for a single session.
type Session interface {
	// Parameters generates a session key, precomputes the SEK/SVK or SEVK, and
	// returns the peer parameter to exchange.
	Parameters(rand io.Reader) ([]byte, error)

	// Encrypt uses a session key to encrypt a payload. Depending on the suite,
	// the result may be a plain COSE_Encrypt0 or one wrapped by COSE_Mac0.
	Encrypt(rand io.Reader, payload any) (cbor.TagData, error)

	// Decrypt a tagged COSE Encrypt0 or Mac0 object.
	Decrypt(rand io.Reader, data cbor.TagData) ([]byte, error)
}
