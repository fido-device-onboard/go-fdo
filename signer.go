// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"crypto/hmac"
	"fmt"

	"github.com/fido-device-onboard/go-fdo/cose"
)

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
