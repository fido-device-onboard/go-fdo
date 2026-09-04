// SPDX-FileCopyrightText: (C) 2024 Intel Corporation & Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fdo

// CapabilityFlags represents FDO capability flags exchanged during protocol negotiation.
type CapabilityFlags struct {
	Flags        []byte
	VendorUnique []string `cbor:",omitempty"`
}

// Capability flag bits for version support (FDO 2.0 spec)
const (
	Capb0SupFDO10 = 1 << 0 // bit 0: Sender supports FDO 1.0
	Capb0SupFDO11 = 1 << 1 // bit 1: Sender supports FDO 1.1
	Capb0SupFDO20 = 1 << 2 // bit 2: Sender supports FDO 2.0
	// Bits 3-6: Reserved, must be zero
	// Bit 7: Delegate support
	DelegateSupportFlag = 1 << 7
)

// VendorUniqueFlags contains vendor-specific capability identifiers.
var VendorUniqueFlags = []string{"com.example.test"}

// GlobalCapabilityFlags is the default set of capability flags advertised by the server.
// Includes version support flags as required by FDO 2.0 spec
var GlobalCapabilityFlags = CapabilityFlags{
	Flags:        []byte{Capb0SupFDO10 | Capb0SupFDO11 | Capb0SupFDO20 | DelegateSupportFlag},
	VendorUnique: VendorUniqueFlags,
}
