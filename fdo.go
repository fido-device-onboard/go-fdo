// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"crypto/hmac"
	"fmt"

	"github.com/fido-device-onboard/go-fdo/cose"
)

// Guid is implemented as a 128-bit cryptographically strong random number.
//
// The Guid type identifies a Device during onboarding, and is replaced each
// time onboarding is successful in the Transfer Ownership 2 (TO2) protocol.
type Guid [16]byte

// Nonce is a byte array with length (16 bytes) 128-bit Random number.
//
// Nonces are used within FIDO Device Onboard to ensure that signatures are
// create on demand and not replayed (i.e., to ensure the "freshness" of
// signatures). When asymmetric digital signatures are used to prove ownership
// of a private key, as in FIDO Device Onboard, an attacker may try to replay
// previously signed messages, to impersonate the true key owner. A secure
// protocol can detect and thwart a replay attack by attaching a unique value
// to the signed data. In this case, we use a nonce, which is a
// cryptographically secure random number chosen by the other party in the
// connection. Since FIDO Device Onboard contains several signatures, more than
// one nonce is used. The reader may use the number of the nonce type to track
// when a nonce is offered and then subsequently returned.
type Nonce [16]byte

// Hash is a crypto hash, with length in bytes preceding. Hashes are computed
// in accordance with FIPS-180-4. See COSE assigned numbers for hash types.
//
//	Hash = [
//	    hashtype: int, ;; negative values possible
//	    hash: bstr
//	]
type Hash struct {
	Algorithm HashAlg
	Value     []byte
}

// An HMAC - RFC2104 - is encoded as a hash.
//
//	HMac = Hash
type Hmac = Hash

// HashAlg is an FDO hashtype enum.
//
//	hashtype = (
//	    SHA256: -16,
//	    SHA384: -43,
//	    HMAC-SHA256: 5,
//	    HMAC-SHA384: 6
//	)
type HashAlg int64

// Hash algorithms
const (
	Sha256Hash     HashAlg = -16
	Sha384Hash     HashAlg = -43
	HmacSha256Hash HashAlg = 5
	HmacSha384Hash HashAlg = 6
)

func (alg HashAlg) String() string {
	switch alg {
	case Sha256Hash:
		return "Sha256Hash"
	case Sha384Hash:
		return "Sha384Hash"
	case HmacSha256Hash:
		return "HmacSha256Hash"
	case HmacSha384Hash:
		return "HmacSha384Hash"
	}
	panic("HashAlg missing switch case(s)")
}

// SigInfo is used to encode parameters for the device attestation signature.
//
// SigInfo flows in both directions, initially from the protocol client
// (eASigInfo), then to the protocol client (eBSigInfo). The types eASigInfo and
// eBSigInfo are intended to clarify these two cases in the protocol message
// descriptions.
//
//	SigInfo = [
//	    sgType: DeviceSgType,
//	    Info: bstr
//	]
//	eASigInfo = SigInfo  ;; from Device to Rendezvous/Owner
//	eBSigInfo = SigInfo  ;; from Owner/Rendezvous to Device
//
//	DeviceSgType //= (
//	    StSECP256R1: ES256,  ;; ECDSA secp256r1 = NIST-P-256 = prime256v1
//	    StSECP384R1: ES384,  ;; ECDSA secp384r1 = NIST-P-384
//	    StRSA2048:   RS256,  ;; RSA 2048 bit
//	    StRSA3072:   RS384,  ;; RSA 3072 bit
//	    StEPID10:    90,     ;; Intel® EPID 1.0 signature
//	    StEPID11:    91      ;; Intel® EPID 1.1 signature
//	)
//
//	COSECompatibleSignatureTypes = (
//	    ES256: -7,  ;; From COSE spec, table 5
//	    ES384: -35, ;; From COSE spec, table 5
//	    ES512: -36  ;; From COSE spec, table 5
//	    RS256: -257,;; From https://datatracker.ietf.org/doc/html/draft-ietf-cose-webauthn-algorithms-05
//	    RS384: -258 ;; From https://datatracker.ietf.org/doc/html/draft-ietf-cose-webauthn-algorithms-05
//	)
type SigInfo struct {
	Type int64
	Info []byte
}

// Signer implements signing and hashing functions with some secret material.
type Signer interface {
	// Hmac encodes the given value to CBOR and calculates the hashed MAC for
	// the given algorithm.
	Hmac(HashAlg, any) (Hmac, error)

	// Sign encodes the given payload to CBOR and then signs it as a COSE Sign1
	// signature structure.
	Sign(any) (*cose.Sign1[any], error)
}

// HmacVerify encodes the given value to CBOR and verifies that the given HMAC
// matches it. If the cryptographic portion of verification fails, then
// ErrCryptoVerifyFailed is wrapped.
func HmacVerify(dc Signer, h1 Hmac, v any) error {
	h2, err := dc.Hmac(h1.Algorithm, v)
	if err != nil {
		return err
	}
	if !hmac.Equal(h1.Value, h2.Value) {
		return fmt.Errorf("%w: hmac did not match", ErrCryptoVerifyFailed)
	}
	return nil
}
