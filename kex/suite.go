// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package kex

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"log/slog"

	"github.com/fido-device-onboard/go-fdo/cose"
)

// Available returns whether the given key exchange and cipher suites are both
// available.
func Available(suite Suite, cipher CipherSuiteID) bool {
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

// Valid returns whether the spec allows the key exchange suite for the given
// device and owner attestation keys. The device parameter must be either an
// *ecdsa.PublicKey, *rsa.PublicKey, or cose.SignatureAlgorithm.
//
// (3.6.5) Key Exchange and FIDO Device Onboard Crypto Mapping
//
//	┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
//	│ Device Attestation    Owner Attestation           Key Exchange                                                      │
//	├─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
//	│ ECDSA NIST P-256      RSA2048 or RSA2048RESTR     DHKEXid14/ASYMKEX2048                                             │
//	│ ECDSA NIST P-384      RSA2048 or RSA2048RESTR     DHKEXid14/ASYMKEX2048 (Not a recommended configuration, see note) │
//	│ ECDSA NIST P-256      RSA3072                     DHKEXid15/ASYMKEX3072 (Not a recommended configuration, see note) │
//	│ ECDSA NIST P-384      RSA3072                     DHKEXid15/ASYMKEX3072                                             │
//	│ ECDSA NIST P-256      ECDSA NIST P-256            ECDH256                                                           │
//	│ ECDSA NIST P-384      ECDSA NIST P-256            ECDH256 (Not a recommended configuration) *                       │
//	│ ECDSA NIST P-256      ECDSA NIST P-384            ECDH384 (Not a recommended configuration, see note)               │
//	│ ECDSA NIST P-384      ECDSA NIST P-384            ECDH384                                                           │
//	└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
func (s Suite) Valid(device, owner crypto.PublicKey) bool { //nolint:gocyclo
	var deviceIsP256, deviceIsP384, deviceIsRSA bool
	switch deviceKey := device.(type) {
	case *rsa.PublicKey:
		deviceIsRSA = true
	case *ecdsa.PublicKey:
		deviceIsP256 = deviceKey.Curve == elliptic.P256()
		deviceIsP384 = deviceKey.Curve == elliptic.P384()
	case cose.SignatureAlgorithm:
		switch deviceKey {
		case cose.RS256Alg, cose.RS384Alg, cose.PS256Alg, cose.PS384Alg:
			deviceIsRSA = true
		case cose.ES256Alg:
			deviceIsP256 = true
		case cose.ES384Alg:
			deviceIsP384 = true
		}
	}
	if deviceIsRSA {
		// FDO version 1.1 says nothing about key exchanges allowed for devices
		// using RSA keys
		return true
	}

	var ownerIsP256, ownerIsP384, ownerIsRSA2048, ownerIsRSA3072 bool
	switch ownerKey := owner.(type) {
	case *ecdsa.PublicKey:
		ownerIsP256 = ownerKey.Curve == elliptic.P256()
		ownerIsP384 = ownerKey.Curve == elliptic.P384()
	case *rsa.PublicKey:
		ownerIsRSA2048 = ownerKey.Size() == 2048/8
		ownerIsRSA3072 = ownerKey.Size() == 3072/8
	}

	switch {
	case deviceIsP256 && ownerIsRSA2048 && (s == DHKEXid14Suite || s == ASYMKEX2048Suite):
		return true
	case deviceIsP384 && ownerIsRSA2048 && (s == DHKEXid14Suite || s == ASYMKEX2048Suite):
		slog.Warn("Device P-384/Owner RSA2048 is not a recommended configuration")
		return true
	case deviceIsP256 && ownerIsRSA3072 && (s == DHKEXid15Suite || s == ASYMKEX3072Suite):
		slog.Warn("Device P-256/Owner RSA3072 is not a recommended configuration")
		return true
	case deviceIsP384 && ownerIsRSA3072 && (s == DHKEXid15Suite || s == ASYMKEX3072Suite):
		return true
	case deviceIsP256 && ownerIsP256 && s == ECDH256Suite:
		return true
	case deviceIsP384 && ownerIsP256 && s == ECDH256Suite:
		slog.Warn("Device P-384/Owner P-256 is not a recommended configuration")
		return true
	case deviceIsP256 && ownerIsP384 && s == ECDH384Suite:
		slog.Warn("Device P-256/Owner P-384 is not a recommended configuration")
		return true
	case deviceIsP384 && ownerIsP384 && s == ECDH384Suite:
		return true
	}
	return false
}

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
