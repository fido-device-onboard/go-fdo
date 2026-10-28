// SPDX-FileCopyrightText: (C) 2024 Intel Corporation & Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fdo

// CapabilityFlags represents FDO capability flags exchanged during protocol negotiation.
type CapabilityFlags struct {
	Flags        []byte
	VendorUnique []string
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

// ExampleVendorFlag is an EXAMPLE vendor capability flag (VendorCapFlags,
// reverse domain name notation). It demonstrates the mechanism only and
// enables no behavior. Implementations should replace it with their own
// registered flags, or advertise none (see GlobalCapabilityFlags).
const ExampleVendorFlag = "com.example.test"

// VendorUniqueFlags contains the vendor-specific capability flags that are
// advertised. It only holds ExampleVendorFlag, as an example.
var VendorUniqueFlags = []string{ExampleVendorFlag}

// GlobalCapabilityFlags is the default set of capability flags advertised in
// every FDO 2.0 message that carries them: FDO 1.1 and 2.0 (this library
// does not implement FDO 1.0) and Delegate support.
//
// To advertise no vendor flags, set VendorUnique to an empty, non-nil slice
// (VendorCapFlags is a CBOR array and must not be encoded as null):
//
//	fdo.GlobalCapabilityFlags.VendorUnique = []string{}
var GlobalCapabilityFlags = CapabilityFlags{
	Flags:        []byte{Capb0SupFDO11 | Capb0SupFDO20 | DelegateSupportFlag},
	VendorUnique: VendorUniqueFlags,
}
