// SPDX-FileCopyrightText: (C) 2024 Intel Corporation & Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fdo

// CapabilityFlags represents FDO capability flags exchanged during protocol negotiation.
type CapabilityFlags struct {
	Flags        []byte
	VendorUnique []string `cbor:",omitempty"`
}

// DelegateSupportFlag indicates the server supports delegate certificates.
const (
	DelegateSupportFlag = 1
)

// VendorUniqueFlags contains vendor-specific capability identifiers.
var VendorUniqueFlags = []string{"com.example.test"}

// GlobalCapabilityFlags is the default set of capability flags advertised by the server.
var GlobalCapabilityFlags = CapabilityFlags{
	Flags:        []byte{DelegateSupportFlag}, // Delegate support
	VendorUnique: VendorUniqueFlags,
}
