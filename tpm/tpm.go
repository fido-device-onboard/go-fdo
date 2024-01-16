// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package tpm

import (
	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
)

type DeviceKeyType uint8

// DeviceKeyType enum as defined in section 4.1
//
// 0: FDO key (device key is derived from Unique String)
// 1: The IDevID in the TPM
// 2: An LDevID in the TPM
const (
	FdoDeviceKey    DeviceKeyType = 0
	IDevIdDeviceKey DeviceKeyType = 1
	LDevIdDeviceKey DeviceKeyType = 2
)

// DeviceCredential implements the FDO Signer interface and conforms to the
// [TPM Draft Spec](https://fidoalliance.org/specs/FDO/securing-fdo-in-tpm-v1.0-rd-20231010/securing-fdo-in-tpm-v1.0-rd-20231010.html).
type DeviceCredential struct {
	fdo.DeviceCredential
	DeviceKey       DeviceKeyType
	DeviceKeyHandle uint32

	// Path to the TPM resource manager
	TpmRmPath string `cbor:"-"`
}

var _ fdo.Signer = (*DeviceCredential)(nil)

// Hmac encodes the given value to CBOR and calculates the hashed MAC for the
// given algorithm.
func (dc *DeviceCredential) Hmac(alg fdo.HashAlg, payload any) (fdo.Hmac, error) {
	panic("unimplemented")
}

// Sign encodes the given payload to CBOR and then signs it as a COSE Sign1
// signature structure.
func (dc *DeviceCredential) Sign(payload any) (*cose.Sign1[any], error) {
	s1 := cose.Sign1[any]{Payload: cbor.NewBstrPtr(payload)}
	if err := s1.Sign(nil, nil, &cose.SignFuncOptions{
		// TODO: Select real parameters
		Algorithm: cose.ES256Alg,
		Sign: func([]byte) ([]byte, error) {
			panic("unimplemented")
		},
	}); err != nil {
		return nil, err
	}
	return &s1, nil
}

// TODO: Helper methods for loading/storing to TPM
