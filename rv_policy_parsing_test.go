// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo_test

import (
	"testing"

	"github.com/fido-device-onboard/go-fdo"
)

// TestVoucherReplacementPolicyParsing tests the policy string parsing
func TestVoucherReplacementPolicyParsing(t *testing.T) {
	tests := []struct {
		input     string
		expected  fdo.VoucherReplacementPolicy
		shouldErr bool
	}{
		{"allow-any", fdo.RVPolicyAllowAny, false},
		{"0", fdo.RVPolicyAllowAny, false},
		{"manufacturer-key-consistency", fdo.RVPolicyManufacturerKeyConsistency, false},
		{"1", fdo.RVPolicyManufacturerKeyConsistency, false},
		{"first-registration-lock", fdo.RVPolicyFirstRegistrationLock, false},
		{"2", fdo.RVPolicyFirstRegistrationLock, false},
		{"owner-key-consistency", fdo.RVPolicyOwnerKeyConsistency, false},
		{"3", fdo.RVPolicyOwnerKeyConsistency, false},
		{"invalid", fdo.RVPolicyAllowAny, true},
		{"99", fdo.RVPolicyAllowAny, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			policy, err := fdo.ParseVoucherReplacementPolicy(tt.input)

			if tt.shouldErr {
				if err == nil {
					t.Errorf("expected error for input %q but got none", tt.input)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for input %q: %v", tt.input, err)
				}
				if policy != tt.expected {
					t.Errorf("expected policy %v for input %q, got %v", tt.expected, tt.input, policy)
				}
			}
		})
	}
}

// TestVoucherReplacementPolicyString tests the String() method
func TestVoucherReplacementPolicyString(t *testing.T) {
	tests := []struct {
		policy   fdo.VoucherReplacementPolicy
		expected string
	}{
		{fdo.RVPolicyAllowAny, "allow-any"},
		{fdo.RVPolicyManufacturerKeyConsistency, "manufacturer-key-consistency"},
		{fdo.RVPolicyFirstRegistrationLock, "first-registration-lock"},
		{fdo.RVPolicyOwnerKeyConsistency, "owner-key-consistency"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.policy.String(); got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}
