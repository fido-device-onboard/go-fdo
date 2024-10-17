// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package tpm

import (
	"fmt"

	"github.com/fido-device-onboard/go-fdo"
)

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

// DeviceCredential marshals to the structure defined in the
// [TPM Draft Spec](https://fidoalliance.org/specs/FDO/securing-fdo-in-tpm-v1.0-rd-20231010/securing-fdo-in-tpm-v1.0-rd-20231010.html).
type DeviceCredential struct {
	DeviceCredential fdo.DeviceCredential
	DeviceKey        DeviceKeyType
	DeviceKeyHandle  uint32
}

func (dc DeviceCredential) String() string {
	s := fmt.Sprintf(`tpmcred[
  Version          %d
  DeviceInfo      %q
  GUID             %x
  PublicKeyHash
    Algorithm      %s
    Value          %x
  DeviceKey        %d
  DeviceKeyHandle  %d
  RvInfo
`, dc.DeviceCredential.Version, dc.DeviceCredential.DeviceInfo, dc.DeviceCredential.GUID, dc.DeviceCredential.PublicKeyHash.Algorithm, dc.DeviceCredential.PublicKeyHash.Value, dc.DeviceKey, dc.DeviceKeyHandle)
	for _, directive := range dc.DeviceCredential.RvInfo {
		s += "    >\n"
		for _, instruction := range directive {
			s += fmt.Sprintf("      %d = %x\n", instruction.Variable, instruction.Value)
		}
	}
	return s + "]"
}
