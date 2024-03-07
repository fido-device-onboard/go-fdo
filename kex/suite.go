// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package kex

// IsValid returns whether the given key exchange and cipher suites are both
// available.
func IsValid(suite Suite, cipher CipherSuiteID) bool {
	_, suiteRegistered := constructors[string(suite)]
	_, cipherRegistered := ciphers[cipher]
	return suiteRegistered && cipherRegistered
}

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

var constructors = make(map[string]func([]byte, CipherSuiteID) Session)

// RegisterKeyExchangeSuite sets a constructor for a Session using a given key
// exchange suite.
func RegisterKeyExchangeSuite(name string, f func([]byte, CipherSuiteID) Session) {
	constructors[name] = f
}

// New returns a Session for the given key exchange suite. If no session
// constructor is registered for the suite, then the return value is nil.
//
// For the server, xA will be nil.
func (s Suite) New(xA []byte, c CipherSuiteID) Session {
	f := constructors[string(s)]
	if f == nil {
		return nil
	}
	return f(xA, c)
}
