// SPDX-FileCopyrightText: (C) 2024 Intel Corporation & Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fdo

// CapabilityFlags represents FDO capability flags exchanged during protocol
// negotiation. Starting with FDO 2.0, capability flags enable version
// negotiation and feature advertisement between devices and owner services.
type CapabilityFlags struct {
	Flags        []byte
	VendorUnique []string `cbor:",omitempty"`
}

// Capability flag bits for version support (FDO 2.0 spec, section 3.3.3).
const (
	Capb0SupFDO10       = 1 << 0 // bit 0: Sender supports FDO 1.0
	Capb0SupFDO11       = 1 << 1 // bit 1: Sender supports FDO 1.1
	Capb0SupFDO20       = 1 << 2 // bit 2: Sender supports FDO 2.0
	DelegateSupportFlag = 1 << 7 // bit 7: Sender supports Delegation
)

// GlobalCapabilityFlags is the default set of capability flags advertised by
// the server. Includes version support flags for both FDO 1.1 and 2.0, and
// delegate support, as required by FDO 2.0 spec.
var GlobalCapabilityFlags = CapabilityFlags{
	Flags: []byte{Capb0SupFDO10 | Capb0SupFDO11 | Capb0SupFDO20 | DelegateSupportFlag},
}

// SupportsVersion returns true if the capability flags indicate support for
// the given FDO major.minor version. The version parameter should be one of
// the Capb0Sup* constants.
func (c *CapabilityFlags) SupportsVersion(flag byte) bool {
	if c == nil || len(c.Flags) == 0 {
		return false
	}
	return c.Flags[0]&flag != 0
}

// SupportsDelegate returns true if the capability flags indicate support for
// delegation.
func (c *CapabilityFlags) SupportsDelegate() bool {
	if c == nil || len(c.Flags) == 0 {
		return false
	}
	return c.Flags[0]&DelegateSupportFlag != 0
}
