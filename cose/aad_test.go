// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cose

import (
	"bytes"
	"testing"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// TestAADTagsAreNonEmpty verifies that all AAD domain tags have been
// successfully encoded (not nil/empty). A nil AAD tag would effectively
// disable domain separation for that operation.
func TestAADTagsAreNonEmpty(t *testing.T) {
	tags := map[string][]byte{
		"AADOwnerSign":        AADOwnerSign,
		"AADProveToRV":        AADProveToRV,
		"AADProveDevice":      AADProveDevice,
		"AADProveOVHdr":       AADProveOVHdr,
		"AADSetupDevice":      AADSetupDevice,
		"AADOVEntry":          AADOVEntry,
		"AADKeyAuthChallenge": AADKeyAuthChallenge,
		"AADKeyAuthProve":     AADKeyAuthProve,
		"AADMetaPayload":      AADMetaPayload,
		"AADBmoProvision":     AADBmoProvision,
	}

	for name, tag := range tags {
		t.Run(name, func(t *testing.T) {
			if len(tag) == 0 {
				t.Errorf("%s is empty", name)
			}
		})
	}
}

// TestAADTagsAreValidCBOR verifies that each AAD tag is valid CBOR that
// decodes to a single-element string array [tstr] as specified by:
//
//	FDOExternalAAD = [FDODomainTag]
//	FDODomainTag = tstr
func TestAADTagsAreValidCBOR(t *testing.T) {
	tags := map[string][]byte{
		"AADOwnerSign":        AADOwnerSign,
		"AADProveToRV":        AADProveToRV,
		"AADProveDevice":      AADProveDevice,
		"AADProveOVHdr":       AADProveOVHdr,
		"AADSetupDevice":      AADSetupDevice,
		"AADOVEntry":          AADOVEntry,
		"AADKeyAuthChallenge": AADKeyAuthChallenge,
		"AADKeyAuthProve":     AADKeyAuthProve,
		"AADMetaPayload":      AADMetaPayload,
		"AADBmoProvision":     AADBmoProvision,
	}

	for name, tag := range tags {
		t.Run(name, func(t *testing.T) {
			var decoded []string
			if err := cbor.Unmarshal(tag, &decoded); err != nil {
				t.Fatalf("failed to unmarshal AAD tag as []string: %v", err)
			}
			if len(decoded) != 1 {
				t.Fatalf("AAD tag should contain exactly 1 element, got %d", len(decoded))
			}
			if decoded[0] == "" {
				t.Fatal("AAD domain tag string is empty")
			}
		})
	}
}

// TestAADTagsAreUnique verifies that each AAD domain tag has a unique
// encoded value. Duplicate tags would break domain separation between
// protocol operations.
func TestAADTagsAreUnique(t *testing.T) {
	tags := map[string][]byte{
		"AADOwnerSign":        AADOwnerSign,
		"AADProveToRV":        AADProveToRV,
		"AADProveDevice":      AADProveDevice,
		"AADProveOVHdr":       AADProveOVHdr,
		"AADSetupDevice":      AADSetupDevice,
		"AADOVEntry":          AADOVEntry,
		"AADKeyAuthChallenge": AADKeyAuthChallenge,
		"AADKeyAuthProve":     AADKeyAuthProve,
		"AADMetaPayload":      AADMetaPayload,
		"AADBmoProvision":     AADBmoProvision,
	}

	seen := make(map[string]string) // encoded bytes -> tag name
	for name, tag := range tags {
		key := string(tag)
		if other, ok := seen[key]; ok {
			t.Errorf("SECURITY: %s and %s have identical encoded AAD values", name, other)
		}
		seen[key] = name
	}
}

// TestAADDomainTagStrings verifies the expected domain tag string values
// for each AAD tag. These strings are part of the protocol specification
// and must not change without a specification revision.
func TestAADDomainTagStrings(t *testing.T) {
	tests := []struct {
		name     string
		aad      []byte
		expected string
	}{
		{"AADOwnerSign", AADOwnerSign, "FDO-TO0-OwnerSign-v1"},
		{"AADProveToRV", AADProveToRV, "FDO-TO1-ProveToRV-v1"},
		{"AADProveDevice", AADProveDevice, "FDO-TO2-ProveDevice-v1"},
		{"AADProveOVHdr", AADProveOVHdr, "FDO-TO2-ProveOVHdr-v1"},
		{"AADSetupDevice", AADSetupDevice, "FDO-TO2-SetupDevice-v1"},
		{"AADOVEntry", AADOVEntry, "FDO-OVEntry-v1"},
		{"AADKeyAuthChallenge", AADKeyAuthChallenge, "FDO-KeyAuth-Challenge-v1"},
		{"AADKeyAuthProve", AADKeyAuthProve, "FDO-KeyAuth-Prove-v1"},
		{"AADMetaPayload", AADMetaPayload, "FDO-FSIM-MetaPayload-v1"},
		{"AADBmoProvision", AADBmoProvision, "FDO-FSIM-BmoProvision-v1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var decoded []string
			if err := cbor.Unmarshal(tt.aad, &decoded); err != nil {
				t.Fatalf("failed to decode: %v", err)
			}
			if decoded[0] != tt.expected {
				t.Errorf("domain tag = %q, want %q", decoded[0], tt.expected)
			}
		})
	}
}

// TestAADSharedBetweenVersions verifies that the same AAD domain tags are
// used for both FDO 1.1 and FDO 2.0 variants of the same operation.
// Per the spec comments: "Tags are intent-based: the same tag is used for
// both v1.01 and v2.0 message variants of the same operation."
//
// This is critical for cross-version verification: a signature created with
// FDO 1.1 ProveDevice (type 64) uses the same AAD as FDO 2.0 ProveDevice20
// (type 82), so a verifier doesn't need to know which version produced it.
func TestAADSharedBetweenVersions(t *testing.T) {
	// Verify ProveDevice AAD ends with -v1 (shared across versions)
	var proveDevice []string
	if err := cbor.Unmarshal(AADProveDevice, &proveDevice); err != nil {
		t.Fatalf("failed to decode AADProveDevice: %v", err)
	}
	if proveDevice[0] != "FDO-TO2-ProveDevice-v1" {
		t.Errorf("AADProveDevice tag = %q, expected shared v1 tag", proveDevice[0])
	}

	// Verify ProveOVHdr AAD ends with -v1 (shared across versions)
	var proveOVHdr []string
	if err := cbor.Unmarshal(AADProveOVHdr, &proveOVHdr); err != nil {
		t.Fatalf("failed to decode AADProveOVHdr: %v", err)
	}
	if proveOVHdr[0] != "FDO-TO2-ProveOVHdr-v1" {
		t.Errorf("AADProveOVHdr tag = %q, expected shared v1 tag", proveOVHdr[0])
	}

	// Verify SetupDevice AAD ends with -v1 (shared across versions)
	var setupDevice []string
	if err := cbor.Unmarshal(AADSetupDevice, &setupDevice); err != nil {
		t.Fatalf("failed to decode AADSetupDevice: %v", err)
	}
	if setupDevice[0] != "FDO-TO2-SetupDevice-v1" {
		t.Errorf("AADSetupDevice tag = %q, expected shared v1 tag", setupDevice[0])
	}
}

// TestAADRoundTrip verifies that encoding a domain tag and then decoding it
// produces the exact same bytes, ensuring deterministic CBOR encoding.
func TestAADRoundTrip(t *testing.T) {
	tags := []struct {
		name string
		tag  string
	}{
		{"FDO-TO0-OwnerSign-v1", "FDO-TO0-OwnerSign-v1"},
		{"FDO-TO2-ProveDevice-v1", "FDO-TO2-ProveDevice-v1"},
		{"FDO-OVEntry-v1", "FDO-OVEntry-v1"},
	}

	for _, tt := range tags {
		t.Run(tt.name, func(t *testing.T) {
			encoded := mustEncodeDomainAAD(tt.tag)

			// Decode and re-encode
			var decoded []string
			if err := cbor.Unmarshal(encoded, &decoded); err != nil {
				t.Fatalf("failed to decode: %v", err)
			}

			reencoded, err := cbor.Marshal(decoded)
			if err != nil {
				t.Fatalf("failed to re-encode: %v", err)
			}

			if !bytes.Equal(encoded, reencoded) {
				t.Errorf("round-trip produced different bytes: original=% x, reencoded=% x", encoded, reencoded)
			}
		})
	}
}

// TestAADProtocolGrouping verifies that AAD tags are grouped by protocol
// operation as expected by the specification.
func TestAADProtocolGrouping(t *testing.T) {
	decode := func(aad []byte) string {
		var s []string
		if err := cbor.Unmarshal(aad, &s); err != nil {
			t.Fatalf("decode error: %v", err)
		}
		return s[0]
	}

	t.Run("TO0 operations", func(t *testing.T) {
		tag := decode(AADOwnerSign)
		if tag[:8] != "FDO-TO0-" {
			t.Errorf("AADOwnerSign should start with FDO-TO0-, got %q", tag)
		}
	})

	t.Run("TO1 operations", func(t *testing.T) {
		tag := decode(AADProveToRV)
		if tag[:8] != "FDO-TO1-" {
			t.Errorf("AADProveToRV should start with FDO-TO1-, got %q", tag)
		}
	})

	t.Run("TO2 operations", func(t *testing.T) {
		to2Tags := map[string][]byte{
			"AADProveDevice": AADProveDevice,
			"AADProveOVHdr":  AADProveOVHdr,
			"AADSetupDevice": AADSetupDevice,
		}
		for name, aad := range to2Tags {
			tag := decode(aad)
			if tag[:8] != "FDO-TO2-" {
				t.Errorf("%s should start with FDO-TO2-, got %q", name, tag)
			}
		}
	})

	t.Run("KeyAuth operations", func(t *testing.T) {
		keyAuthTags := map[string][]byte{
			"AADKeyAuthChallenge": AADKeyAuthChallenge,
			"AADKeyAuthProve":     AADKeyAuthProve,
		}
		for name, aad := range keyAuthTags {
			tag := decode(aad)
			if tag[:12] != "FDO-KeyAuth-" {
				t.Errorf("%s should start with FDO-KeyAuth-, got %q", name, tag)
			}
		}
	})

	t.Run("FSIM operations", func(t *testing.T) {
		fsimTags := map[string][]byte{
			"AADMetaPayload":  AADMetaPayload,
			"AADBmoProvision": AADBmoProvision,
		}
		for name, aad := range fsimTags {
			tag := decode(aad)
			if tag[:9] != "FDO-FSIM-" {
				t.Errorf("%s should start with FDO-FSIM-, got %q", name, tag)
			}
		}
	})
}
