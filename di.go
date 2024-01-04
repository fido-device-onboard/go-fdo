// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
)

// Signer implements COSE sign/verify and HMAC hash/verify functions.
type Signer interface {
	// Hmac encodes the given value to CBOR and calculates the hashed MAC for
	// the given algorithm.
	Hmac(HashAlg, any) (Hmac, error)

	// HmacVerify encodes the given value to CBOR and verifies that the given
	// HMAC matches it.
	HmacVerify(Hmac, any) error

	// Sign encodes the given payload to CBOR and performs signs it as a COSE
	// Sign1 signature structure.
	Sign(any) (cose.Sign1[any], error)

	// Verify uses the same private material as Sign to verify the given COSE
	// Sign1 signature structure.
	Verify(cose.Sign1[any]) error
}

// DeviceCredential is non-normative, but the [TPM Draft Spec] proposes a CBOR
// encoding, so that will be used.
//
//	DCTPM = [
//	    DCProtVer: protver,
//	    DCDeviceInfo: tstr,
//	    DCGuid: bstr
//	    DCRVInfo: RendezvousInfo,
//	    DCPubKeyHash: Hash
//	    DeviceKeyType: uint
//	    DeviceKeyHandle: uint
//	]
//
// [TPM Draft Spec]: https://fidoalliance.org/specs/FDO/securing-fdo-in-tpm-v1.0-rd-20231010/securing-fdo-in-tpm-v1.0-rd-20231010.html
type DeviceCredential struct {
	Version         uint16
	DeviceInfo      string
	Guid            []byte
	RvInfo          []RvInstruction
	PublicKeyHash   Hash
	DeviceKeyType   uint64
	DeviceKeyHandle uint64
}

type DeviceCredentialTPM struct {
	DeviceCredential

	// TODO
	TpmPath string `cbor:"-"`
}

// TODO
func (dc *DeviceCredentialTPM) Hmac(alg HashAlg, payload any) (Hmac, error)

// TODO
func (dc *DeviceCredentialTPM) Sign(payload []byte) (cose.Sign1[cbor.RawBytes], error)

// DeviceCredentialBlob contains all device state, including both public and private
// parts of keys and secrets.
type DeviceCredentialBlob struct {
	DeviceCredential

	Active     bool
	HmacType   int64
	HmacSecret []byte
	PrivateKey []byte // PKCS#8
}

// TODO: Add interface implemented by both DeviceCredentialTPM and
// DeviceCredentialBlob that handles Sign/Verify and Hmac/HmacVerify.
