// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cose

import (
	"bytes"
	"testing"

	"github.com/fido-device-onboard/go-fdo/v2/cbor"
)

func TestAADTagsNonEmpty(t *testing.T) {
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
		if len(tag) == 0 {
			t.Errorf("%s is empty", name)
		}
	}
}

func TestAADTagsValidCBOR(t *testing.T) {
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
		var decoded []string
		if err := cbor.Unmarshal(tag, &decoded); err != nil {
			t.Errorf("%s: failed to decode as CBOR array of strings: %v", name, err)
			continue
		}
		if len(decoded) != 1 {
			t.Errorf("%s: expected 1-element array, got %d elements", name, len(decoded))
		}
		if decoded[0] == "" {
			t.Errorf("%s: domain tag string is empty", name)
		}
	}
}

func TestAADTagsUnique(t *testing.T) {
	tags := []struct {
		name string
		val  []byte
	}{
		{"AADOwnerSign", AADOwnerSign},
		{"AADProveToRV", AADProveToRV},
		{"AADProveDevice", AADProveDevice},
		{"AADProveOVHdr", AADProveOVHdr},
		{"AADSetupDevice", AADSetupDevice},
		{"AADOVEntry", AADOVEntry},
		{"AADKeyAuthChallenge", AADKeyAuthChallenge},
		{"AADKeyAuthProve", AADKeyAuthProve},
		{"AADMetaPayload", AADMetaPayload},
		{"AADBmoProvision", AADBmoProvision},
	}
	for i := range tags {
		for j := i + 1; j < len(tags); j++ {
			if bytes.Equal(tags[i].val, tags[j].val) {
				t.Errorf("duplicate AAD tags: %s and %s", tags[i].name, tags[j].name)
			}
		}
	}
}

func TestAADDomainStrings(t *testing.T) {
	expected := map[string]string{
		"AADOwnerSign":        "FDO-TO0-OwnerSign-v1",
		"AADProveToRV":        "FDO-TO1-ProveToRV-v1",
		"AADProveDevice":      "FDO-TO2-ProveDevice-v1",
		"AADProveOVHdr":       "FDO-TO2-ProveOVHdr-v1",
		"AADSetupDevice":      "FDO-TO2-SetupDevice-v1",
		"AADOVEntry":          "FDO-OVEntry-v1",
		"AADKeyAuthChallenge": "FDO-KeyAuth-Challenge-v1",
		"AADKeyAuthProve":     "FDO-KeyAuth-Prove-v1",
		"AADMetaPayload":      "FDO-FSIM-MetaPayload-v1",
		"AADBmoProvision":     "FDO-FSIM-BmoProvision-v1",
	}
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
		var decoded []string
		if err := cbor.Unmarshal(tag, &decoded); err != nil {
			t.Errorf("%s: decode error: %v", name, err)
			continue
		}
		want := expected[name]
		if decoded[0] != want {
			t.Errorf("%s: expected domain string %q, got %q", name, want, decoded[0])
		}
	}
}

func TestAADRoundTrip(t *testing.T) {
	tag := "FDO-Test-RoundTrip-v1"
	encoded := mustEncodeDomainAAD(tag)
	var decoded []string
	if err := cbor.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if len(decoded) != 1 || decoded[0] != tag {
		t.Errorf("round trip failed: got %v, want [%q]", decoded, tag)
	}
}

func TestLegacyAliases(t *testing.T) {
	if !bytes.Equal(AADTO0OwnerSign, AADOwnerSign) {
		t.Error("AADTO0OwnerSign != AADOwnerSign")
	}
	if !bytes.Equal(AADTO1ProveToRV, AADProveToRV) {
		t.Error("AADTO1ProveToRV != AADProveToRV")
	}
	if !bytes.Equal(AADTO2ProveDevice, AADProveDevice) {
		t.Error("AADTO2ProveDevice != AADProveDevice")
	}
	if !bytes.Equal(AADTO2ProveOVHdr, AADProveOVHdr) {
		t.Error("AADTO2ProveOVHdr != AADProveOVHdr")
	}
	if !bytes.Equal(AADTO2SetupDevice, AADSetupDevice) {
		t.Error("AADTO2SetupDevice != AADSetupDevice")
	}
}
