// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo_test

import (
	"testing"

	"github.com/fido-device-onboard/go-fdo"
)

func TestCapabilityFlags_SupportsVersion(t *testing.T) {
	tests := []struct {
		name     string
		flags    *fdo.CapabilityFlags
		version  byte
		expected bool
	}{
		{
			name:     "nil flags",
			flags:    nil,
			version:  fdo.Capb0SupFDO20,
			expected: false,
		},
		{
			name:     "empty flags",
			flags:    &fdo.CapabilityFlags{Flags: []byte{}},
			version:  fdo.Capb0SupFDO20,
			expected: false,
		},
		{
			name:     "supports FDO 2.0",
			flags:    &fdo.CapabilityFlags{Flags: []byte{fdo.Capb0SupFDO20}},
			version:  fdo.Capb0SupFDO20,
			expected: true,
		},
		{
			name:     "supports FDO 1.1",
			flags:    &fdo.CapabilityFlags{Flags: []byte{fdo.Capb0SupFDO11}},
			version:  fdo.Capb0SupFDO11,
			expected: true,
		},
		{
			name:     "supports multiple versions",
			flags:    &fdo.CapabilityFlags{Flags: []byte{fdo.Capb0SupFDO10 | fdo.Capb0SupFDO11 | fdo.Capb0SupFDO20}},
			version:  fdo.Capb0SupFDO20,
			expected: true,
		},
		{
			name:     "does not support requested version",
			flags:    &fdo.CapabilityFlags{Flags: []byte{fdo.Capb0SupFDO11}},
			version:  fdo.Capb0SupFDO20,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.flags.SupportsVersion(tt.version)
			if result != tt.expected {
				t.Errorf("SupportsVersion() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestCapabilityFlags_SupportsDelegate(t *testing.T) {
	tests := []struct {
		name     string
		flags    *fdo.CapabilityFlags
		expected bool
	}{
		{
			name:     "nil flags",
			flags:    nil,
			expected: false,
		},
		{
			name:     "empty flags",
			flags:    &fdo.CapabilityFlags{Flags: []byte{}},
			expected: false,
		},
		{
			name:     "supports delegation",
			flags:    &fdo.CapabilityFlags{Flags: []byte{fdo.DelegateSupportFlag}},
			expected: true,
		},
		{
			name:     "does not support delegation",
			flags:    &fdo.CapabilityFlags{Flags: []byte{fdo.Capb0SupFDO20}},
			expected: false,
		},
		{
			name:     "supports FDO 2.0 and delegation",
			flags:    &fdo.CapabilityFlags{Flags: []byte{fdo.Capb0SupFDO20 | fdo.DelegateSupportFlag}},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.flags.SupportsDelegate()
			if result != tt.expected {
				t.Errorf("SupportsDelegate() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGlobalCapabilityFlags(t *testing.T) {
	// Verify GlobalCapabilityFlags has expected capabilities
	if !fdo.GlobalCapabilityFlags.SupportsVersion(fdo.Capb0SupFDO10) {
		t.Error("GlobalCapabilityFlags should support FDO 1.0")
	}
	if !fdo.GlobalCapabilityFlags.SupportsVersion(fdo.Capb0SupFDO11) {
		t.Error("GlobalCapabilityFlags should support FDO 1.1")
	}
	if !fdo.GlobalCapabilityFlags.SupportsVersion(fdo.Capb0SupFDO20) {
		t.Error("GlobalCapabilityFlags should support FDO 2.0")
	}
	if !fdo.GlobalCapabilityFlags.SupportsDelegate() {
		t.Error("GlobalCapabilityFlags should support delegation")
	}
}
