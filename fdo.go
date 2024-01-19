// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package fdo implements version 1.1 of the FDO protocol.
package fdo

// GUID is implemented as a 128-bit cryptographically strong random number.
//
// The GUID type identifies a Device during onboarding, and is replaced each
// time onboarding is successful in the Transfer Ownership 2 (TO2) protocol.
type GUID [16]byte

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
//	    PS256: -37, ;; From IANA
//	    PS384: -38, ;; From IANA
//	    RS256: -257,;; From https://datatracker.ietf.org/doc/html/draft-ietf-cose-webauthn-algorithms-05
//	    RS384: -258 ;; From https://datatracker.ietf.org/doc/html/draft-ietf-cose-webauthn-algorithms-05
//	)
type SigInfo struct {
	Type int64
	Info []byte
}
