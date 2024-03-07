// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package tpm implements device credentials using the
// [TPM Draft Spec](https://fidoalliance.org/specs/FDO/securing-fdo-in-tpm-v1.0-rd-20231010/securing-fdo-in-tpm-v1.0-rd-20231010.html).
package tpm

import (
	"crypto"
	"hash"
	"io"

	"github.com/fido-device-onboard/go-fdo"
)

// DeviceKeyType enumerates how DeviceKey is encoded and stored.
type DeviceKeyType uint8

// DeviceKeyType enum as defined in section 4.1
//
// 0: FDO key (device key is derived from Unique String)
// 1: The IDevID in the TPM
// 2: An LDevID in the TPM
const (
	FdoDeviceKey    DeviceKeyType = 0
	IDevIDDeviceKey DeviceKeyType = 1
	LDevIDDeviceKey DeviceKeyType = 2
)

// DeviceCredential implements the signing and hmac interfaces and conforms to the
// [TPM Draft Spec](https://fidoalliance.org/specs/FDO/securing-fdo-in-tpm-v1.0-rd-20231010/securing-fdo-in-tpm-v1.0-rd-20231010.html).
type DeviceCredential struct {
	fdo.DeviceCredential
	DeviceKey       DeviceKeyType
	DeviceKeyHandle uint32

	// Path to the TPM resource manager
	TpmRmPath string `cbor:"-"`
}

var _ fdo.KeyedHasher = (*DeviceCredential)(nil)

// NewHmac returns a key-based hash (Hmac) using the given hash function some
// secret.
func (dc *DeviceCredential) NewHmac(alg fdo.HashAlg) hash.Hash {
	panic("unimplemented")
}

// Supports returns whether a particular HashAlg is supported.
func (dc *DeviceCredential) Supports(alg fdo.HashAlg) bool {
	panic("unimplemented")
}

var _ crypto.Signer = (*DeviceCredential)(nil)

// Public returns the corresponding public key.
func (dc *DeviceCredential) Public() crypto.PublicKey {
	panic("unimplemented")
}

// Sign signs digest with the private key.
func (dc *DeviceCredential) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	panic("unimplemented")
}

// TODO: Helper methods for loading/storing to TPM
