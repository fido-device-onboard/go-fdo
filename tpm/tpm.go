// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package tpm

import (
	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cose"
)

// DeviceCredential implements the FDO Signer interface and conforms to the
// [TPM Draft Spec](https://fidoalliance.org/specs/FDO/securing-fdo-in-tpm-v1.0-rd-20231010/securing-fdo-in-tpm-v1.0-rd-20231010.html).
type DeviceCredential struct {
	fdo.DeviceCredential
	DeviceKeyType   uint64
	DeviceKeyHandle uint64

	// Path to the TPM resource manager
	TpmRmPath string `cbor:"-"`
}

var _ fdo.Signer = (*DeviceCredential)(nil)

// Hmac encodes the given value to CBOR and calculates the hashed MAC for the
// given algorithm.
func (dc *DeviceCredential) Hmac(alg fdo.HashAlg, payload any) (fdo.Hmac, error) {
	panic("unimplemented")
}

// HmacVerify encodes the given value to CBOR and verifies that the given HMAC
// matches it.
func (dc *DeviceCredential) HmacVerify(h fdo.Hmac, v any) error {
	panic("unimplemented")
}

// Sign encodes the given payload to CBOR and performs signs it as a COSE Sign1
// signature structure.
func (dc *DeviceCredential) Sign(payload any) (cose.Sign1[any], error) {
	panic("unimplemented")
}

// Verify uses the same private material as Sign to verify the given COSE Sign1
// signature structure.
func (dc *DeviceCredential) Verify(v cose.Sign1[any]) error {
	panic("unimplemented")
}

// TODO: Helper methods for loading/storing to TPM
