// SPDX-FileCopyrightText: (C) 2024 Intel Corporation & Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fdo

type CapabilityFlags struct {
	Flags        []byte
	VendorUnique []string `cbor:",omitempty"`
}

const (
	DelegateSupportFlag = 1
)

var VendorUniqueFlags = []string{"com.example.test"}

// These are based on ntants
var GlobalCapabilityFlags = CapabilityFlags{
	Flags:        []byte{DelegateSupportFlag}, // Delegate support
	VendorUnique: VendorUniqueFlags,
}
