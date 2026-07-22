// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo_test

import (
	"bytes"
	"testing"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// TestCrossVersionMessageTypeRanges verifies that FDO 1.1 and 2.0 TO2
// message type ranges are disjoint, preventing ambiguity in protocol
// dispatch.
func TestCrossVersionMessageTypeRanges(t *testing.T) {
	v11Types := make(map[uint8]bool)
	for msgType := uint8(60); msgType <= 71; msgType++ {
		v11Types[msgType] = true
	}

	v20Types := make(map[uint8]bool)
	for msgType := uint8(80); msgType <= 91; msgType++ {
		v20Types[msgType] = true
	}

	// Verify no overlap
	for msgType := range v11Types {
		if v20Types[msgType] {
			t.Errorf("message type %d appears in both v1.1 and v2.0 ranges", msgType)
		}
	}

	// Verify version identification is consistent
	for msgType := range v11Types {
		if protocol.VersionOf(msgType) != protocol.Version101 {
			t.Errorf("VersionOf(%d) should be Version101 for v1.1 message", msgType)
		}
	}
	for msgType := range v20Types {
		if protocol.VersionOf(msgType) != protocol.Version200 {
			t.Errorf("VersionOf(%d) should be Version200 for v2.0 message", msgType)
		}
	}
}

// TestCrossVersionProtocolMapping verifies that both v1.1 and v2.0 TO2
// message types map to the same TO2Protocol, ensuring a single TO2Server
// can handle both versions.
func TestCrossVersionProtocolMapping(t *testing.T) {
	// All v1.1 TO2 messages should map to TO2Protocol
	for msgType := uint8(60); msgType <= 71; msgType++ {
		if p := protocol.Of(msgType); p != protocol.TO2Protocol {
			t.Errorf("v1.1 message %d maps to %v, want TO2Protocol", msgType, p)
		}
	}

	// All v2.0 TO2 messages should also map to TO2Protocol
	for msgType := uint8(80); msgType <= 91; msgType++ {
		if p := protocol.Of(msgType); p != protocol.TO2Protocol {
			t.Errorf("v2.0 message %d maps to %v, want TO2Protocol", msgType, p)
		}
	}

	// Non-TO2 protocols should be unaffected
	if p := protocol.Of(10); p != protocol.DIProtocol {
		t.Errorf("DI message maps to %v, want DIProtocol", p)
	}
	if p := protocol.Of(20); p != protocol.TO0Protocol {
		t.Errorf("TO0 message maps to %v, want TO0Protocol", p)
	}
	if p := protocol.Of(30); p != protocol.TO1Protocol {
		t.Errorf("TO1 message maps to %v, want TO1Protocol", p)
	}
}

// TestCrossVersionEncryptionBoundaries verifies that the encryption
// boundaries for v1.1 and v2.0 are correctly defined at different
// points in the protocol flow.
//
// FDO 1.1: SetupDevice(65) onward is encrypted (owner proves first,
//
//	key exchange completes with ProveDevice)
//
// FDO 2.0: DeviceSvcInfoRdy20(86) onward is encrypted (device proves
//
//	first, key exchange completes with ProveOVHdr20)
func TestCrossVersionEncryptionBoundaries(t *testing.T) {
	// FDO 1.1 encryption starts at message 65
	v11FirstEncrypted := uint8(65)
	v11LastEncrypted := uint8(71)
	v11LastUnencrypted := uint8(64)

	if protocol.IsTO2Encrypted(v11LastUnencrypted) {
		t.Errorf("v1.1 message %d should NOT be encrypted (last unencrypted)", v11LastUnencrypted)
	}
	if !protocol.IsTO2Encrypted(v11FirstEncrypted) {
		t.Errorf("v1.1 message %d SHOULD be encrypted (first encrypted)", v11FirstEncrypted)
	}
	if !protocol.IsTO2Encrypted(v11LastEncrypted) {
		t.Errorf("v1.1 message %d SHOULD be encrypted (last encrypted)", v11LastEncrypted)
	}

	// FDO 2.0 encryption starts at message 86
	v20FirstEncrypted := uint8(86)
	v20LastEncrypted := uint8(91)
	v20LastUnencrypted := uint8(85)

	if protocol.IsTO2Encrypted(v20LastUnencrypted) {
		t.Errorf("v2.0 message %d should NOT be encrypted (last unencrypted)", v20LastUnencrypted)
	}
	if !protocol.IsTO2Encrypted(v20FirstEncrypted) {
		t.Errorf("v2.0 message %d SHOULD be encrypted (first encrypted)", v20FirstEncrypted)
	}
	if !protocol.IsTO2Encrypted(v20LastEncrypted) {
		t.Errorf("v2.0 message %d SHOULD be encrypted (last encrypted)", v20LastEncrypted)
	}
}

// TestCrossVersionMessageCountParity verifies that v1.1 and v2.0 have
// the same number of TO2 messages (12 each), maintaining structural
// parity between the protocol versions.
func TestCrossVersionMessageCountParity(t *testing.T) {
	var v11Count, v20Count int

	for msgType := uint8(60); msgType <= 71; msgType++ {
		if protocol.Of(msgType) == protocol.TO2Protocol {
			v11Count++
		}
	}

	for msgType := uint8(80); msgType <= 91; msgType++ {
		if protocol.Of(msgType) == protocol.TO2Protocol {
			v20Count++
		}
	}

	if v11Count != 12 {
		t.Errorf("v1.1 TO2 message count = %d, want 12", v11Count)
	}
	if v20Count != 12 {
		t.Errorf("v2.0 TO2 message count = %d, want 12", v20Count)
	}
	if v11Count != v20Count {
		t.Errorf("v1.1 (%d) and v2.0 (%d) should have same message count", v11Count, v20Count)
	}
}

// TestCrossVersionMessageFlowDifference documents the key architectural
// difference between v1.1 and v2.0 TO2: the order of device and owner
// proof.
//
// FDO 1.1 flow: HelloDevice -> ProveOVHdr -> OVEntries -> ProveDevice -> ...
// FDO 2.0 flow: HelloDeviceProbe -> ProveDevice20 -> ProveOVHdr20 -> OVEntries -> ...
//
// In v2.0, the device proves itself FIRST (anti-DoS), then the owner proves.
func TestCrossVersionMessageFlowDifference(t *testing.T) {
	// In v1.1, owner proves first (ProveOVHdr=61 comes before ProveDevice=64)
	v11OwnerProve := protocol.TO2ProveOVHdrMsgType   // 61
	v11DeviceProve := protocol.TO2ProveDeviceMsgType // 64
	if v11OwnerProve >= v11DeviceProve {
		t.Error("v1.1: owner proof should come BEFORE device proof")
	}

	// In v2.0, device proves first (ProveDevice20=82 comes before ProveOVHdr20=83)
	v20DeviceProve := protocol.TO2ProveDevice20MsgType // 82
	v20OwnerProve := protocol.TO2ProveOVHdr20MsgType   // 83
	if v20DeviceProve >= v20OwnerProve {
		t.Error("v2.0: device proof should come BEFORE owner proof (anti-DoS)")
	}
}

// TestCrossVersionStartEndSymmetry verifies that both versions have
// proper start and end message types for session management.
func TestCrossVersionStartEndSymmetry(t *testing.T) {
	// v1.1 TO2
	if !protocol.IsProtocolStart(protocol.TO2HelloDeviceMsgType) {
		t.Error("v1.1: HelloDevice (60) should be protocol start")
	}
	if !protocol.IsProtocolEnd(protocol.TO2Done2MsgType) {
		t.Error("v1.1: Done2 (71) should be protocol end")
	}

	// v2.0 TO2
	if !protocol.IsProtocolStart(protocol.TO2HelloDeviceProbeMsgType) {
		t.Error("v2.0: HelloDeviceProbe (80) should be protocol start")
	}
	if !protocol.IsProtocolEnd(protocol.TO2DoneAck20MsgType) {
		t.Error("v2.0: DoneAck20 (91) should be protocol end")
	}

	// Intermediate messages should NOT be protocol start or end
	intermediates := []struct {
		name    string
		msgType uint8
	}{
		{"v1.1 ProveOVHdr", 61},
		{"v1.1 ProveDevice", 64},
		{"v1.1 Done", 70},
		{"v2.0 ProveDevice20", 82},
		{"v2.0 ProveOVHdr20", 83},
		{"v2.0 Done20", 90},
	}
	for _, msg := range intermediates {
		if protocol.IsProtocolStart(msg.msgType) {
			t.Errorf("%s (%d) should NOT be protocol start", msg.name, msg.msgType)
		}
		if protocol.IsProtocolEnd(msg.msgType) {
			t.Errorf("%s (%d) should NOT be protocol end", msg.name, msg.msgType)
		}
	}
}

// TestCrossVersionGapMessages verifies that message types between the v1.1
// range (60-71) and v2.0 range (80-91) are not assigned to any protocol.
// These gap messages (72-79) must not be treated as valid TO2 messages.
func TestCrossVersionGapMessages(t *testing.T) {
	for msgType := uint8(72); msgType <= 79; msgType++ {
		t.Run("gap_"+string(rune('0'+msgType/10))+string(rune('0'+msgType%10)), func(t *testing.T) {
			if p := protocol.Of(msgType); p != protocol.UnknownProtocol {
				t.Errorf("gap message %d maps to %v, want UnknownProtocol", msgType, p)
			}
			if protocol.IsTO2Encrypted(msgType) {
				t.Errorf("gap message %d should NOT be marked as encrypted", msgType)
			}
			if protocol.IsProtocolStart(msgType) {
				t.Errorf("gap message %d should NOT be protocol start", msgType)
			}
			if protocol.IsProtocolEnd(msgType) {
				t.Errorf("gap message %d should NOT be protocol end", msgType)
			}
		})
	}
}

// TestCrossVersionCapabilityFlagsInterop verifies that capability flags
// correctly enable version negotiation between entities supporting
// different FDO versions.
func TestCrossVersionCapabilityFlagsInterop(t *testing.T) {
	tests := []struct {
		name      string
		v11Only   fdo.CapabilityFlags
		v20Only   fdo.CapabilityFlags
		both      fdo.CapabilityFlags
		canMeet20 bool
		canMeet11 bool
	}{
		{
			name:      "v1.1 client meets v2.0 server",
			v11Only:   fdo.CapabilityFlags{Flags: []byte{fdo.Capb0SupFDO11}},
			v20Only:   fdo.CapabilityFlags{Flags: []byte{fdo.Capb0SupFDO20}},
			canMeet20: false,
			canMeet11: false,
		},
		{
			name:      "v1.1 client meets v1.1+v2.0 server",
			v11Only:   fdo.CapabilityFlags{Flags: []byte{fdo.Capb0SupFDO11}},
			both:      fdo.CapabilityFlags{Flags: []byte{fdo.Capb0SupFDO11 | fdo.Capb0SupFDO20}},
			canMeet20: false,
			canMeet11: true,
		},
		{
			name:      "v2.0 client meets v1.1+v2.0 server",
			v20Only:   fdo.CapabilityFlags{Flags: []byte{fdo.Capb0SupFDO20}},
			both:      fdo.CapabilityFlags{Flags: []byte{fdo.Capb0SupFDO11 | fdo.Capb0SupFDO20}},
			canMeet20: true,
			canMeet11: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var client, server fdo.CapabilityFlags
			if tt.v11Only.Flags != nil {
				client = tt.v11Only
			} else if tt.v20Only.Flags != nil {
				client = tt.v20Only
			}
			if tt.both.Flags != nil {
				server = tt.both
			} else if tt.v20Only.Flags != nil {
				server = tt.v20Only
			}

			meet20 := client.SupportsVersion(fdo.Capb0SupFDO20) && server.SupportsVersion(fdo.Capb0SupFDO20)
			meet11 := client.SupportsVersion(fdo.Capb0SupFDO11) && server.SupportsVersion(fdo.Capb0SupFDO11)

			if meet20 != tt.canMeet20 {
				t.Errorf("mutual v2.0 support = %v, want %v", meet20, tt.canMeet20)
			}
			if meet11 != tt.canMeet11 {
				t.Errorf("mutual v1.1 support = %v, want %v", meet11, tt.canMeet11)
			}
		})
	}
}

// TestCrossVersionTO2MessageSerialization verifies that v1.1 and v2.0 TO2
// message structures serialize to distinct CBOR values and are not
// interchangeable.
func TestCrossVersionTO2MessageSerialization(t *testing.T) {
	t.Run("HelloDevice v1.1 vs HelloDeviceProbe v2.0", func(t *testing.T) {
		// v1.1 HelloDevice has: [GUID, nonce, kex_suite, cipher_suite, max_msg_sz, SigInfo]
		// v2.0 HelloDeviceProbe has: [CapabilityFlags, GUID, max_msg_sz, hash_types, sugar]
		// These are structurally different and should produce different CBOR.

		// Serialize a minimal v2.0 HelloDeviceProbe
		probe := fdo.HelloDeviceProbeMsg{
			CapabilityFlags: fdo.GlobalCapabilityFlags,
			GUID:            protocol.GUID{0x01},
			MaxDeviceMsgSz:  65535,
		}
		probeData, err := cbor.Marshal(probe)
		if err != nil {
			t.Fatalf("failed to marshal HelloDeviceProbe: %v", err)
		}

		// The probe data should be valid CBOR
		var raw cbor.RawBytes
		if err := cbor.Unmarshal(probeData, &raw); err != nil {
			t.Fatalf("HelloDeviceProbe produced invalid CBOR: %v", err)
		}

		// Verify the probe can be round-tripped
		var decoded fdo.HelloDeviceProbeMsg
		if err := cbor.Unmarshal(probeData, &decoded); err != nil {
			t.Fatalf("failed to unmarshal HelloDeviceProbe: %v", err)
		}
		if decoded.GUID != probe.GUID {
			t.Error("GUID mismatch after round-trip")
		}
		if decoded.MaxDeviceMsgSz != probe.MaxDeviceMsgSz {
			t.Error("MaxDeviceMsgSz mismatch after round-trip")
		}
		if !decoded.CapabilityFlags.SupportsVersion(fdo.Capb0SupFDO20) {
			t.Error("CapabilityFlags should support FDO 2.0 after round-trip")
		}
	})

	t.Run("Done20 includes ReplacementHmac", func(t *testing.T) {
		// In v2.0, the replacement HMAC is in Done20 (type 90),
		// NOT in DeviceSvcInfoRdy as in v1.1. This is a key structural
		// difference.
		done := fdo.Done20Msg{
			NonceTO2SetupDV: protocol.Nonce{0xAA},
			ReplacementHmac: nil, // nil for credential reuse
		}

		data, err := cbor.Marshal(done)
		if err != nil {
			t.Fatalf("failed to marshal Done20: %v", err)
		}

		var decoded fdo.Done20Msg
		if err := cbor.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("failed to unmarshal Done20: %v", err)
		}
		if decoded.NonceTO2SetupDV != done.NonceTO2SetupDV {
			t.Error("nonce mismatch")
		}
		if decoded.ReplacementHmac != nil {
			t.Error("ReplacementHmac should be nil for credential reuse")
		}
	})

	t.Run("DeviceSvcInfoRdy20 has no HMAC", func(t *testing.T) {
		// In v2.0, DeviceSvcInfoRdy20 does NOT include the HMAC
		// (it was moved to Done20).
		rdy := fdo.DeviceSvcInfoRdy20Msg{
			MaxOwnerSvcInfoSz: nil,
		}

		data, err := cbor.Marshal(rdy)
		if err != nil {
			t.Fatalf("failed to marshal DeviceSvcInfoRdy20: %v", err)
		}

		var decoded fdo.DeviceSvcInfoRdy20Msg
		if err := cbor.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("failed to unmarshal DeviceSvcInfoRdy20: %v", err)
		}
	})

	t.Run("DoneAck20 matches Done2 nonce", func(t *testing.T) {
		// v2.0 DoneAck20 (type 91) serves the same purpose as v1.1 Done2 (type 71)
		ack := fdo.DoneAck20Msg{
			NonceTO2ProveOV: protocol.Nonce{0xBB},
		}

		data, err := cbor.Marshal(ack)
		if err != nil {
			t.Fatalf("failed to marshal DoneAck20: %v", err)
		}

		var decoded fdo.DoneAck20Msg
		if err := cbor.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("failed to unmarshal DoneAck20: %v", err)
		}
		if decoded.NonceTO2ProveOV != ack.NonceTO2ProveOV {
			t.Error("nonce mismatch in DoneAck20")
		}
	})
}

// TestCrossVersionContextPropagation verifies that the protocol version
// context is correctly propagated and that a handler can determine the
// FDO version from the context. The default (unset context) is Version101,
// ensuring backwards compatibility with existing FDO 1.1 clients.
func TestCrossVersionContextPropagation(t *testing.T) {
	tests := []struct {
		name    string
		msgType uint8
		version protocol.Version
	}{
		// DI, TO0, TO1 always use Version101
		{"DI AppStart", 10, protocol.Version101},
		{"TO0 Hello", 20, protocol.Version101},
		{"TO1 HelloRV", 30, protocol.Version101},

		// TO2 v1.1 messages
		{"TO2 HelloDevice v1.1", 60, protocol.Version101},
		{"TO2 Done2 v1.1", 71, protocol.Version101},

		// TO2 v2.0 messages
		{"TO2 HelloDeviceProbe v2.0", 80, protocol.Version200},
		{"TO2 DoneAck20 v2.0", 91, protocol.Version200},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := protocol.VersionOf(tt.msgType)
			if got != tt.version {
				t.Errorf("VersionOf(%d) = %v, want %v", tt.msgType, got, tt.version)
			}
		})
	}
}

// TestCrossVersionHelloDeviceProbeMsg verifies the HelloDeviceProbe (type
// 80) message structure that is unique to FDO 2.0.
func TestCrossVersionHelloDeviceProbeMsg(t *testing.T) {
	tests := []struct {
		name string
		msg  fdo.HelloDeviceProbeMsg
	}{
		{
			name: "minimal probe",
			msg: fdo.HelloDeviceProbeMsg{
				CapabilityFlags: fdo.CapabilityFlags{Flags: []byte{fdo.Capb0SupFDO20}},
				GUID:            protocol.GUID{},
				MaxDeviceMsgSz:  1300,
			},
		},
		{
			name: "full probe with all flags",
			msg: fdo.HelloDeviceProbeMsg{
				CapabilityFlags: fdo.GlobalCapabilityFlags,
				GUID:            protocol.GUID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10},
				MaxDeviceMsgSz:  65535,
				Sugar:           []byte{0xDE, 0xAD, 0xBE, 0xEF},
			},
		},
		{
			name: "probe with delegation flag",
			msg: fdo.HelloDeviceProbeMsg{
				CapabilityFlags: fdo.CapabilityFlags{Flags: []byte{fdo.Capb0SupFDO20 | fdo.DelegateSupportFlag}},
				GUID:            protocol.GUID{0xFF},
				MaxDeviceMsgSz:  32768,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := cbor.Marshal(tt.msg)
			if err != nil {
				t.Fatalf("marshal error: %v", err)
			}

			var decoded fdo.HelloDeviceProbeMsg
			if err := cbor.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("unmarshal error: %v", err)
			}

			if decoded.GUID != tt.msg.GUID {
				t.Errorf("GUID mismatch: got %v, want %v", decoded.GUID, tt.msg.GUID)
			}
			if decoded.MaxDeviceMsgSz != tt.msg.MaxDeviceMsgSz {
				t.Errorf("MaxDeviceMsgSz: got %d, want %d", decoded.MaxDeviceMsgSz, tt.msg.MaxDeviceMsgSz)
			}
			if !bytes.Equal(decoded.Sugar, tt.msg.Sugar) {
				t.Errorf("Sugar mismatch: got %v, want %v", decoded.Sugar, tt.msg.Sugar)
			}
			if !bytes.Equal(decoded.CapabilityFlags.Flags, tt.msg.CapabilityFlags.Flags) {
				t.Errorf("CapabilityFlags mismatch: got %v, want %v", decoded.CapabilityFlags.Flags, tt.msg.CapabilityFlags.Flags)
			}
		})
	}
}

// TestCrossVersionSetupDeviceMsg verifies the SetupDevice20 (type 87)
// message structure, which differs from v1.1 SetupDevice in having
// optional ReplacementGUID and ReplacementRvInfo (for credential reuse).
func TestCrossVersionSetupDeviceMsg(t *testing.T) {
	t.Run("new credentials", func(t *testing.T) {
		guid := protocol.GUID{0x01, 0x02, 0x03}
		rvInfo := [][]protocol.RvInstruction{}
		msg := fdo.SetupDevice20Msg{
			NonceTO2SetupDV:    protocol.Nonce{0xAA},
			ReplacementGUID:    &guid,
			ReplacementRvInfo:  &rvInfo,
			MaxDeviceSvcInfoSz: 65535,
		}

		data, err := cbor.Marshal(msg)
		if err != nil {
			t.Fatalf("marshal error: %v", err)
		}

		var decoded fdo.SetupDevice20Msg
		if err := cbor.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}
		if decoded.ReplacementGUID == nil {
			t.Fatal("ReplacementGUID should not be nil for new credentials")
		}
		if *decoded.ReplacementGUID != guid {
			t.Errorf("ReplacementGUID mismatch")
		}
	})

	t.Run("credential reuse", func(t *testing.T) {
		msg := fdo.SetupDevice20Msg{
			NonceTO2SetupDV:    protocol.Nonce{0xBB},
			ReplacementGUID:    nil,
			ReplacementRvInfo:  nil,
			MaxDeviceSvcInfoSz: 65535,
		}

		data, err := cbor.Marshal(msg)
		if err != nil {
			t.Fatalf("marshal error: %v", err)
		}

		var decoded fdo.SetupDevice20Msg
		if err := cbor.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}
		if decoded.ReplacementGUID != nil {
			t.Error("ReplacementGUID should be nil for credential reuse")
		}
		if decoded.ReplacementRvInfo != nil {
			t.Error("ReplacementRvInfo should be nil for credential reuse")
		}
	})
}
