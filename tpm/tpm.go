// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package tpm implements device credentials using the
// [TPM Draft Spec](https://fidoalliance.org/specs/FDO/securing-fdo-in-tpm-v1.0-rd-20231010/securing-fdo-in-tpm-v1.0-rd-20231010.html).
package tpm

import (
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
