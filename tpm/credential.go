// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package tpm

// DeviceKeyType enumerates how DeviceKey is encoded and stored.
type DeviceKeyType uint8

// DeviceKeyType enum as defined in section 4.1
//
//	0: FDO key (device key is derived from Unique String)
//	1: The IDevID in the TPM
//	2: An LDevID in the TPM
const (
	FdoDeviceKey    DeviceKeyType = 0
	IDevIDDeviceKey DeviceKeyType = 1
	LDevIDDeviceKey DeviceKeyType = 2
)
