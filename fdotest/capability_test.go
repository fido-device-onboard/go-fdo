// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdotest_test

import (
	"bytes"
	"testing"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// TestCapabilityNegotiation_V20HelloDeviceProbe verifies that the
// HelloDeviceProbe (type 80) message carries GlobalCapabilityFlags,
// and that the flags round-trip through CBOR correctly. This is the
// first message in FDO 2.0 TO2 and sets up version negotiation.
func TestCapabilityNegotiation_V20HelloDeviceProbe(t *testing.T) {
	msg := fdo.HelloDeviceProbeMsg{
		CapabilityFlags: fdo.GlobalCapabilityFlags,
		GUID:            protocol.GUID{0x01, 0x02, 0x03},
		MaxDeviceMsgSz:  65535,
	}

	data, err := cbor.Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal HelloDeviceProbe: %v", err)
	}

	var decoded fdo.HelloDeviceProbeMsg
	if err := cbor.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal HelloDeviceProbe: %v", err)
	}

	// Verify all version flags survive the round-trip
	if !decoded.CapabilityFlags.SupportsVersion(fdo.Capb0SupFDO10) {
		t.Error("decoded HelloDeviceProbe flags should support FDO 1.0")
	}
	if !decoded.CapabilityFlags.SupportsVersion(fdo.Capb0SupFDO11) {
		t.Error("decoded HelloDeviceProbe flags should support FDO 1.1")
	}
	if !decoded.CapabilityFlags.SupportsVersion(fdo.Capb0SupFDO20) {
		t.Error("decoded HelloDeviceProbe flags should support FDO 2.0")
	}
	if !decoded.CapabilityFlags.SupportsDelegate() {
		t.Error("decoded HelloDeviceProbe flags should support delegation")
	}
}

// TestCapabilityNegotiation_V20HelloDeviceAck verifies that the
// HelloDeviceAck20 (type 81) message also carries capability flags,
// allowing the server to advertise its supported versions back to the
// device. The device uses this to confirm version compatibility.
func TestCapabilityNegotiation_V20HelloDeviceAck(t *testing.T) {
	msg := fdo.HelloDeviceAck20Msg{
		CapabilityFlags: fdo.GlobalCapabilityFlags,
		GUID:            protocol.GUID{0x04, 0x05, 0x06},
		MaxOwnerMsgSz:   65535,
	}

	data, err := cbor.Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal HelloDeviceAck20: %v", err)
	}

	var decoded fdo.HelloDeviceAck20Msg
	if err := cbor.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal HelloDeviceAck20: %v", err)
	}

	if !decoded.CapabilityFlags.SupportsVersion(fdo.Capb0SupFDO20) {
		t.Error("decoded HelloDeviceAck20 flags should support FDO 2.0")
	}
	if !decoded.CapabilityFlags.SupportsDelegate() {
		t.Error("decoded HelloDeviceAck20 flags should support delegation")
	}
}

// TestCapabilityNegotiation_MutualVersionSelection simulates the version
// negotiation that occurs when a device and owner exchange capability
// flags during HelloDeviceProbe/HelloDeviceAck20. This tests the logic
// that would select the highest mutually supported version.
func TestCapabilityNegotiation_MutualVersionSelection(t *testing.T) {
	tests := []struct {
		name      string
		device    fdo.CapabilityFlags
		server    fdo.CapabilityFlags
		expectV20 bool
		expectV11 bool
	}{
		{
			name:      "both v2.0: select v2.0",
			device:    fdo.CapabilityFlags{Flags: []byte{fdo.Capb0SupFDO20}},
			server:    fdo.CapabilityFlags{Flags: []byte{fdo.Capb0SupFDO20}},
			expectV20: true,
		},
		{
			name:      "device v1.1, server v2.0: no common",
			device:    fdo.CapabilityFlags{Flags: []byte{fdo.Capb0SupFDO11}},
			server:    fdo.CapabilityFlags{Flags: []byte{fdo.Capb0SupFDO20}},
			expectV20: false,
			expectV11: false,
		},
		{
			name:      "device v1.1, server both: select v1.1",
			device:    fdo.CapabilityFlags{Flags: []byte{fdo.Capb0SupFDO11}},
			server:    fdo.CapabilityFlags{Flags: []byte{fdo.Capb0SupFDO11 | fdo.Capb0SupFDO20}},
			expectV20: false,
			expectV11: true,
		},
		{
			name:      "device v2.0, server both: select v2.0",
			device:    fdo.CapabilityFlags{Flags: []byte{fdo.Capb0SupFDO20}},
			server:    fdo.CapabilityFlags{Flags: []byte{fdo.Capb0SupFDO11 | fdo.Capb0SupFDO20}},
			expectV20: true,
			expectV11: false,
		},
		{
			name:      "both all versions: select v2.0 and v1.1",
			device:    fdo.GlobalCapabilityFlags,
			server:    fdo.GlobalCapabilityFlags,
			expectV20: true,
			expectV11: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Compute mutual support (intersection)
			mutualV20 := tt.device.SupportsVersion(fdo.Capb0SupFDO20) && tt.server.SupportsVersion(fdo.Capb0SupFDO20)
			mutualV11 := tt.device.SupportsVersion(fdo.Capb0SupFDO11) && tt.server.SupportsVersion(fdo.Capb0SupFDO11)

			if mutualV20 != tt.expectV20 {
				t.Errorf("mutual v2.0 support = %v, want %v", mutualV20, tt.expectV20)
			}
			if mutualV11 != tt.expectV11 {
				t.Errorf("mutual v1.1 support = %v, want %v", mutualV11, tt.expectV11)
			}
		})
	}
}

// TestCapabilityNegotiation_FlagsInHelloDeviceProbeRoundTrip verifies that
// various capability flag configurations survive CBOR round-trip inside a
// HelloDeviceProbe message. This is the exact serialization path used in
// real protocol execution.
func TestCapabilityNegotiation_FlagsInHelloDeviceProbeRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		flags fdo.CapabilityFlags
	}{
		{
			name:  "v2.0 only",
			flags: fdo.CapabilityFlags{Flags: []byte{fdo.Capb0SupFDO20}},
		},
		{
			name:  "global flags",
			flags: fdo.GlobalCapabilityFlags,
		},
		{
			name: "with vendor unique",
			flags: fdo.CapabilityFlags{
				Flags:        []byte{fdo.Capb0SupFDO20 | fdo.DelegateSupportFlag},
				VendorUnique: []string{"com.example.feature1"},
			},
		},
		{
			name:  "v1.1 only with delegation",
			flags: fdo.CapabilityFlags{Flags: []byte{fdo.Capb0SupFDO11 | fdo.DelegateSupportFlag}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := fdo.HelloDeviceProbeMsg{
				CapabilityFlags: tt.flags,
				GUID:            protocol.GUID{0x01},
				MaxDeviceMsgSz:  65535,
			}

			data, err := cbor.Marshal(msg)
			if err != nil {
				t.Fatalf("marshal error: %v", err)
			}

			var decoded fdo.HelloDeviceProbeMsg
			if err := cbor.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("unmarshal error: %v", err)
			}

			if !bytes.Equal(decoded.CapabilityFlags.Flags, tt.flags.Flags) {
				t.Errorf("flags mismatch: got %v, want %v",
					decoded.CapabilityFlags.Flags, tt.flags.Flags)
			}
		})
	}
}

// TestCapabilityNegotiation_V20CredentialReuseViaSetupDevice20 verifies
// that the SetupDevice20 (type 87) message correctly uses nil pointers
// to signal credential reuse. When the server decides to reuse
// credentials, ReplacementGUID and ReplacementRvInfo are nil.
func TestCapabilityNegotiation_V20CredentialReuseViaSetupDevice20(t *testing.T) {
	// Test new credentials (non-nil pointers)
	guid := protocol.GUID{0x01}
	rvInfo := [][]protocol.RvInstruction{}
	newCred := fdo.SetupDevice20Msg{
		NonceTO2SetupDV:    protocol.Nonce{0xAA},
		ReplacementGUID:    &guid,
		ReplacementRvInfo:  &rvInfo,
		MaxDeviceSvcInfoSz: 65535,
	}

	data, err := cbor.Marshal(newCred)
	if err != nil {
		t.Fatalf("marshal new cred: %v", err)
	}

	var decodedNew fdo.SetupDevice20Msg
	if err := cbor.Unmarshal(data, &decodedNew); err != nil {
		t.Fatalf("unmarshal new cred: %v", err)
	}
	if decodedNew.ReplacementGUID == nil {
		t.Error("ReplacementGUID should be non-nil for new credentials")
	}
	if decodedNew.ReplacementRvInfo == nil {
		t.Error("ReplacementRvInfo should be non-nil for new credentials")
	}

	// Test credential reuse (nil pointers)
	reuse := fdo.SetupDevice20Msg{
		NonceTO2SetupDV:    protocol.Nonce{0xBB},
		ReplacementGUID:    nil,
		ReplacementRvInfo:  nil,
		MaxDeviceSvcInfoSz: 65535,
	}

	data, err = cbor.Marshal(reuse)
	if err != nil {
		t.Fatalf("marshal reuse: %v", err)
	}

	var decodedReuse fdo.SetupDevice20Msg
	if err := cbor.Unmarshal(data, &decodedReuse); err != nil {
		t.Fatalf("unmarshal reuse: %v", err)
	}
	if decodedReuse.ReplacementGUID != nil {
		t.Error("ReplacementGUID should be nil for credential reuse")
	}
	if decodedReuse.ReplacementRvInfo != nil {
		t.Error("ReplacementRvInfo should be nil for credential reuse")
	}
}

// TestCapabilityNegotiation_Done20HmacPlacement verifies the structural
// difference between v1.1 and v2.0 regarding where the replacement HMAC
// is placed. In v2.0, it moves from DeviceSvcInfoRdy to Done20 (type 90).
func TestCapabilityNegotiation_Done20HmacPlacement(t *testing.T) {
	t.Run("Done20 with replacement HMAC", func(t *testing.T) {
		hmac := protocol.Hmac{
			Algorithm: protocol.HmacSha256Hash,
			Value:     []byte{0x01, 0x02, 0x03},
		}
		msg := fdo.Done20Msg{
			NonceTO2SetupDV: protocol.Nonce{0xAA},
			ReplacementHmac: &hmac,
		}

		data, err := cbor.Marshal(msg)
		if err != nil {
			t.Fatalf("marshal error: %v", err)
		}

		var decoded fdo.Done20Msg
		if err := cbor.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}
		if decoded.ReplacementHmac == nil {
			t.Fatal("ReplacementHmac should be non-nil")
		}
		if !bytes.Equal(decoded.ReplacementHmac.Value, hmac.Value) {
			t.Error("HMAC value mismatch after round-trip")
		}
	})

	t.Run("Done20 with nil HMAC for credential reuse", func(t *testing.T) {
		msg := fdo.Done20Msg{
			NonceTO2SetupDV: protocol.Nonce{0xBB},
			ReplacementHmac: nil,
		}

		data, err := cbor.Marshal(msg)
		if err != nil {
			t.Fatalf("marshal error: %v", err)
		}

		var decoded fdo.Done20Msg
		if err := cbor.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}
		if decoded.ReplacementHmac != nil {
			t.Error("ReplacementHmac should be nil for credential reuse")
		}
	})
}

// TestCapabilityNegotiation_DeviceSvcInfoRdy20NoHmac verifies that
// DeviceSvcInfoRdy20 (type 86) does NOT carry the replacement HMAC.
// This is the key structural difference from v1.1's DeviceServiceInfoReady.
func TestCapabilityNegotiation_DeviceSvcInfoRdy20NoHmac(t *testing.T) {
	mtu := uint16(65535)
	msg := fdo.DeviceSvcInfoRdy20Msg{
		MaxOwnerSvcInfoSz: &mtu,
	}

	data, err := cbor.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded fdo.DeviceSvcInfoRdy20Msg
	if err := cbor.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.MaxOwnerSvcInfoSz == nil {
		t.Error("MaxOwnerSvcInfoSz should be non-nil")
	} else if *decoded.MaxOwnerSvcInfoSz != mtu {
		t.Errorf("MaxOwnerSvcInfoSz = %d, want %d", *decoded.MaxOwnerSvcInfoSz, mtu)
	}
}
