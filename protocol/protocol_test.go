// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package protocol_test

import (
	"context"
	"testing"

	"github.com/fido-device-onboard/go-fdo/protocol"
)

func TestVersionOf(t *testing.T) {
	tests := []struct {
		name     string
		msgType  uint8
		expected protocol.Version
	}{
		// DI messages (10-13) -> Version101
		{"DI AppStart", 10, protocol.Version101},
		{"DI SetCredentials", 11, protocol.Version101},
		{"DI SetHmac", 12, protocol.Version101},
		{"DI Done", 13, protocol.Version101},

		// TO0 messages (20-23) -> Version101
		{"TO0 Hello", 20, protocol.Version101},
		{"TO0 HelloAck", 21, protocol.Version101},
		{"TO0 OwnerSign", 22, protocol.Version101},
		{"TO0 AcceptOwner", 23, protocol.Version101},

		// TO1 messages (30-33) -> Version101
		{"TO1 HelloRV", 30, protocol.Version101},
		{"TO1 HelloRVAck", 31, protocol.Version101},
		{"TO1 ProveToRV", 32, protocol.Version101},
		{"TO1 RVRedirect", 33, protocol.Version101},

		// TO2 v1.1 messages (60-71) -> Version101
		{"TO2 HelloDevice v1.1", 60, protocol.Version101},
		{"TO2 ProveOVHdr v1.1", 61, protocol.Version101},
		{"TO2 GetOVNextEntry v1.1", 62, protocol.Version101},
		{"TO2 OVNextEntry v1.1", 63, protocol.Version101},
		{"TO2 ProveDevice v1.1", 64, protocol.Version101},
		{"TO2 SetupDevice v1.1", 65, protocol.Version101},
		{"TO2 DeviceSvcInfoReady v1.1", 66, protocol.Version101},
		{"TO2 OwnerSvcInfoReady v1.1", 67, protocol.Version101},
		{"TO2 DeviceSvcInfo v1.1", 68, protocol.Version101},
		{"TO2 OwnerSvcInfo v1.1", 69, protocol.Version101},
		{"TO2 Done v1.1", 70, protocol.Version101},
		{"TO2 Done2 v1.1", 71, protocol.Version101},

		// TO2 v2.0 messages (80-91) -> Version200
		{"TO2 HelloDeviceProbe v2.0", 80, protocol.Version200},
		{"TO2 HelloDeviceAck20 v2.0", 81, protocol.Version200},
		{"TO2 ProveDevice20 v2.0", 82, protocol.Version200},
		{"TO2 ProveOVHdr20 v2.0", 83, protocol.Version200},
		{"TO2 GetOVNextEntry20 v2.0", 84, protocol.Version200},
		{"TO2 OVNextEntry20 v2.0", 85, protocol.Version200},
		{"TO2 DeviceSvcInfoRdy20 v2.0", 86, protocol.Version200},
		{"TO2 SetupDevice20 v2.0", 87, protocol.Version200},
		{"TO2 DeviceSvcInfo20 v2.0", 88, protocol.Version200},
		{"TO2 OwnerSvcInfo20 v2.0", 89, protocol.Version200},
		{"TO2 Done20 v2.0", 90, protocol.Version200},
		{"TO2 DoneAck20 v2.0", 91, protocol.Version200},

		// Error message -> Version101
		{"Error", 255, protocol.Version101},

		// Gap messages (not assigned)
		{"Unassigned 0", 0, protocol.Version101},
		{"Unassigned 50", 50, protocol.Version101},
		{"Unassigned 72", 72, protocol.Version101},
		{"Unassigned 79", 79, protocol.Version101},
		{"Unassigned 92", 92, protocol.Version101},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := protocol.VersionOf(tt.msgType)
			if got != tt.expected {
				t.Errorf("VersionOf(%d) = %v, want %v", tt.msgType, got, tt.expected)
			}
		})
	}
}

func TestOf(t *testing.T) {
	tests := []struct {
		name     string
		msgType  uint8
		expected protocol.Protocol
	}{
		// DI messages
		{"DI AppStart", 10, protocol.DIProtocol},
		{"DI SetCredentials", 11, protocol.DIProtocol},
		{"DI SetHmac", 12, protocol.DIProtocol},
		{"DI Done", 13, protocol.DIProtocol},

		// TO0 messages
		{"TO0 Hello", 20, protocol.TO0Protocol},
		{"TO0 HelloAck", 21, protocol.TO0Protocol},
		{"TO0 OwnerSign", 22, protocol.TO0Protocol},
		{"TO0 AcceptOwner", 23, protocol.TO0Protocol},

		// TO1 messages
		{"TO1 HelloRV", 30, protocol.TO1Protocol},
		{"TO1 HelloRVAck", 31, protocol.TO1Protocol},
		{"TO1 ProveToRV", 32, protocol.TO1Protocol},
		{"TO1 RVRedirect", 33, protocol.TO1Protocol},

		// TO2 v1.1 messages -> TO2
		{"TO2 HelloDevice v1.1", 60, protocol.TO2Protocol},
		{"TO2 Done2 v1.1", 71, protocol.TO2Protocol},

		// TO2 v2.0 messages -> also TO2
		{"TO2 HelloDeviceProbe v2.0", 80, protocol.TO2Protocol},
		{"TO2 DoneAck20 v2.0", 91, protocol.TO2Protocol},
		{"TO2 ProveDevice20 v2.0", 82, protocol.TO2Protocol},
		{"TO2 DeviceSvcInfo20 v2.0", 88, protocol.TO2Protocol},

		// Error
		{"Error", 255, protocol.AnyProtocol},

		// Unknown
		{"Unassigned 0", 0, protocol.UnknownProtocol},
		{"Unassigned 50", 50, protocol.UnknownProtocol},
		{"Unassigned 72", 72, protocol.UnknownProtocol},
		{"Unassigned 79", 79, protocol.UnknownProtocol},
		{"Unassigned 92", 92, protocol.UnknownProtocol},
		{"Unassigned 254", 254, protocol.UnknownProtocol},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := protocol.Of(tt.msgType)
			if got != tt.expected {
				t.Errorf("Of(%d) = %v, want %v", tt.msgType, got, tt.expected)
			}
		})
	}
}

// TestOfConsistency verifies that both v1.1 and v2.0 TO2 message types
// return TO2Protocol from Of(), ensuring the protocol dispatcher can route
// both version ranges to the same TO2 server.
func TestOfConsistency(t *testing.T) {
	// All FDO 1.1 TO2 message types
	for msgType := uint8(60); msgType <= 71; msgType++ {
		if protocol.Of(msgType) != protocol.TO2Protocol {
			t.Errorf("Of(%d) should be TO2Protocol for FDO 1.1 TO2 message, got %v", msgType, protocol.Of(msgType))
		}
	}
	// All FDO 2.0 TO2 message types
	for msgType := uint8(80); msgType <= 91; msgType++ {
		if protocol.Of(msgType) != protocol.TO2Protocol {
			t.Errorf("Of(%d) should be TO2Protocol for FDO 2.0 TO2 message, got %v", msgType, protocol.Of(msgType))
		}
	}
}

func TestIsTO2Encrypted(t *testing.T) {
	tests := []struct {
		name     string
		msgType  uint8
		expected bool
	}{
		// FDO 1.1: messages before SetupDevice (65) are NOT encrypted
		{"TO2 HelloDevice v1.1", 60, false},
		{"TO2 ProveOVHdr v1.1", 61, false},
		{"TO2 GetOVNextEntry v1.1", 62, false},
		{"TO2 OVNextEntry v1.1", 63, false},
		{"TO2 ProveDevice v1.1", 64, false},
		// FDO 1.1: SetupDevice (65) through Done2 (71) ARE encrypted
		{"TO2 SetupDevice v1.1", 65, true},
		{"TO2 DeviceSvcInfoReady v1.1", 66, true},
		{"TO2 OwnerSvcInfoReady v1.1", 67, true},
		{"TO2 DeviceSvcInfo v1.1", 68, true},
		{"TO2 OwnerSvcInfo v1.1", 69, true},
		{"TO2 Done v1.1", 70, true},
		{"TO2 Done2 v1.1", 71, true},

		// FDO 2.0: messages before DeviceSvcInfoRdy20 (86) are NOT encrypted
		{"TO2 HelloDeviceProbe v2.0", 80, false},
		{"TO2 HelloDeviceAck20 v2.0", 81, false},
		{"TO2 ProveDevice20 v2.0", 82, false},
		{"TO2 ProveOVHdr20 v2.0", 83, false},
		{"TO2 GetOVNextEntry20 v2.0", 84, false},
		{"TO2 OVNextEntry20 v2.0", 85, false},
		// FDO 2.0: DeviceSvcInfoRdy20 (86) through DoneAck20 (91) ARE encrypted
		{"TO2 DeviceSvcInfoRdy20 v2.0", 86, true},
		{"TO2 SetupDevice20 v2.0", 87, true},
		{"TO2 DeviceSvcInfo20 v2.0", 88, true},
		{"TO2 OwnerSvcInfo20 v2.0", 89, true},
		{"TO2 Done20 v2.0", 90, true},
		{"TO2 DoneAck20 v2.0", 91, true},

		// Non-TO2 messages should NOT be encrypted
		{"DI AppStart", 10, false},
		{"TO0 Hello", 20, false},
		{"TO1 HelloRV", 30, false},
		{"Error", 255, false},

		// Gap messages between v1.1 and v2.0 should NOT be encrypted
		{"Gap 72", 72, false},
		{"Gap 79", 79, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := protocol.IsTO2Encrypted(tt.msgType)
			if got != tt.expected {
				t.Errorf("IsTO2Encrypted(%d) = %v, want %v", tt.msgType, got, tt.expected)
			}
		})
	}
}

func TestIsProtocolStart(t *testing.T) {
	tests := []struct {
		name     string
		msgType  uint8
		expected bool
	}{
		// Protocol start messages
		{"DI AppStart", protocol.DIAppStartMsgType, true},
		{"TO0 Hello", protocol.TO0HelloMsgType, true},
		{"TO1 HelloRV", protocol.TO1HelloRVMsgType, true},
		{"TO2 HelloDevice v1.1", protocol.TO2HelloDeviceMsgType, true},
		{"TO2 HelloDeviceProbe v2.0", protocol.TO2HelloDeviceProbeMsgType, true},

		// Non-start messages
		{"DI SetCredentials", protocol.DISetCredentialsMsgType, false},
		{"DI Done", protocol.DIDoneMsgType, false},
		{"TO0 OwnerSign", protocol.TO0OwnerSignMsgType, false},
		{"TO1 ProveToRV", protocol.TO1ProveToRVMsgType, false},
		{"TO2 ProveDevice v1.1", protocol.TO2ProveDeviceMsgType, false},
		{"TO2 ProveDevice20 v2.0", protocol.TO2ProveDevice20MsgType, false},
		{"TO2 Done v1.1", protocol.TO2DoneMsgType, false},
		{"TO2 Done20 v2.0", protocol.TO2Done20MsgType, false},
		{"Error", protocol.ErrorMsgType, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := protocol.IsProtocolStart(tt.msgType)
			if got != tt.expected {
				t.Errorf("IsProtocolStart(%d) = %v, want %v", tt.msgType, got, tt.expected)
			}
		})
	}
}

func TestIsProtocolEnd(t *testing.T) {
	tests := []struct {
		name     string
		msgType  uint8
		expected bool
	}{
		// Protocol end messages
		{"DI Done", protocol.DIDoneMsgType, true},
		{"TO0 AcceptOwner", protocol.TO0AcceptOwnerMsgType, true},
		{"TO1 RVRedirect", protocol.TO1RVRedirectMsgType, true},
		{"TO2 Done2 v1.1", protocol.TO2Done2MsgType, true},
		{"TO2 DoneAck20 v2.0", protocol.TO2DoneAck20MsgType, true},

		// Non-end messages
		{"DI AppStart", protocol.DIAppStartMsgType, false},
		{"TO0 Hello", protocol.TO0HelloMsgType, false},
		{"TO1 HelloRV", protocol.TO1HelloRVMsgType, false},
		{"TO2 HelloDevice v1.1", protocol.TO2HelloDeviceMsgType, false},
		{"TO2 HelloDeviceProbe v2.0", protocol.TO2HelloDeviceProbeMsgType, false},
		{"TO2 Done v1.1", protocol.TO2DoneMsgType, false},
		{"TO2 Done20 v2.0", protocol.TO2Done20MsgType, false},
		{"Error", protocol.ErrorMsgType, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := protocol.IsProtocolEnd(tt.msgType)
			if got != tt.expected {
				t.Errorf("IsProtocolEnd(%d) = %v, want %v", tt.msgType, got, tt.expected)
			}
		})
	}
}

// TestStartEndPairing verifies that for each protocol, the start and end
// messages are correctly paired and belong to the same protocol.
func TestStartEndPairing(t *testing.T) {
	pairs := []struct {
		name    string
		start   uint8
		end     uint8
		proto   protocol.Protocol
		version protocol.Version
	}{
		{"DI", protocol.DIAppStartMsgType, protocol.DIDoneMsgType, protocol.DIProtocol, protocol.Version101},
		{"TO0", protocol.TO0HelloMsgType, protocol.TO0AcceptOwnerMsgType, protocol.TO0Protocol, protocol.Version101},
		{"TO1", protocol.TO1HelloRVMsgType, protocol.TO1RVRedirectMsgType, protocol.TO1Protocol, protocol.Version101},
		{"TO2 v1.1", protocol.TO2HelloDeviceMsgType, protocol.TO2Done2MsgType, protocol.TO2Protocol, protocol.Version101},
		{"TO2 v2.0", protocol.TO2HelloDeviceProbeMsgType, protocol.TO2DoneAck20MsgType, protocol.TO2Protocol, protocol.Version200},
	}

	for _, p := range pairs {
		t.Run(p.name, func(t *testing.T) {
			if !protocol.IsProtocolStart(p.start) {
				t.Errorf("expected %d to be protocol start", p.start)
			}
			if !protocol.IsProtocolEnd(p.end) {
				t.Errorf("expected %d to be protocol end", p.end)
			}
			if protocol.Of(p.start) != p.proto {
				t.Errorf("start message %d: Of() = %v, want %v", p.start, protocol.Of(p.start), p.proto)
			}
			if protocol.Of(p.end) != p.proto {
				t.Errorf("end message %d: Of() = %v, want %v", p.end, protocol.Of(p.end), p.proto)
			}
			if protocol.VersionOf(p.start) != p.version {
				t.Errorf("start message %d: VersionOf() = %v, want %v", p.start, protocol.VersionOf(p.start), p.version)
			}
			if protocol.VersionOf(p.end) != p.version {
				t.Errorf("end message %d: VersionOf() = %v, want %v", p.end, protocol.VersionOf(p.end), p.version)
			}
		})
	}
}

func TestVersionIsValid(t *testing.T) {
	tests := []struct {
		name     string
		version  protocol.Version
		expected bool
	}{
		{"Version101", protocol.Version101, true},
		{"Version200", protocol.Version200, true},
		{"Zero", protocol.Version(0), false},
		{"Version100", protocol.Version(100), false},
		{"Version102", protocol.Version(102), false},
		{"Version199", protocol.Version(199), false},
		{"Version201", protocol.Version(201), false},
		{"MaxUint16", protocol.Version(65535), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.version.IsValid()
			if got != tt.expected {
				t.Errorf("Version(%d).IsValid() = %v, want %v", tt.version, got, tt.expected)
			}
		})
	}
}

func TestVersionString(t *testing.T) {
	tests := []struct {
		version  protocol.Version
		expected string
	}{
		{protocol.Version101, "101"},
		{protocol.Version200, "200"},
		{protocol.Version(0), "unknown"},
		{protocol.Version(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := tt.version.String()
			if got != tt.expected {
				t.Errorf("Version(%d).String() = %q, want %q", tt.version, got, tt.expected)
			}
		})
	}
}

func TestVersionContext(t *testing.T) {
	t.Run("default is Version101", func(t *testing.T) {
		ctx := context.Background()
		v := protocol.VersionFromContext(ctx)
		if v != protocol.Version101 {
			t.Errorf("VersionFromContext on empty context = %v, want %v", v, protocol.Version101)
		}
	})

	t.Run("set and get Version101", func(t *testing.T) {
		ctx := protocol.ContextWithVersion(context.Background(), protocol.Version101)
		v := protocol.VersionFromContext(ctx)
		if v != protocol.Version101 {
			t.Errorf("VersionFromContext = %v, want %v", v, protocol.Version101)
		}
	})

	t.Run("set and get Version200", func(t *testing.T) {
		ctx := protocol.ContextWithVersion(context.Background(), protocol.Version200)
		v := protocol.VersionFromContext(ctx)
		if v != protocol.Version200 {
			t.Errorf("VersionFromContext = %v, want %v", v, protocol.Version200)
		}
	})

	t.Run("override version", func(t *testing.T) {
		ctx := protocol.ContextWithVersion(context.Background(), protocol.Version101)
		ctx = protocol.ContextWithVersion(ctx, protocol.Version200)
		v := protocol.VersionFromContext(ctx)
		if v != protocol.Version200 {
			t.Errorf("VersionFromContext after override = %v, want %v", v, protocol.Version200)
		}
	})

	t.Run("child context inherits version", func(t *testing.T) {
		ctx := protocol.ContextWithVersion(context.Background(), protocol.Version200)
		child, cancel := context.WithCancel(ctx)
		defer cancel()
		v := protocol.VersionFromContext(child)
		if v != protocol.Version200 {
			t.Errorf("VersionFromContext on child = %v, want %v", v, protocol.Version200)
		}
	})
}

func TestProtocolString(t *testing.T) {
	tests := []struct {
		proto    protocol.Protocol
		expected string
	}{
		{protocol.DIProtocol, "DI"},
		{protocol.TO0Protocol, "TO0"},
		{protocol.TO1Protocol, "TO1"},
		{protocol.TO2Protocol, "TO2"},
		{protocol.AnyProtocol, "Any"},
		{protocol.UnknownProtocol, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := tt.proto.String()
			if got != tt.expected {
				t.Errorf("Protocol.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestVersionOfBoundaries verifies that the boundary between v1.1 and v2.0
// message types is correctly handled. Messages 72-79 (gap between v1.1 TO2
// and v2.0 TO2) should map to Version101 (the default).
func TestVersionOfBoundaries(t *testing.T) {
	// Last v1.1 TO2 message
	if v := protocol.VersionOf(71); v != protocol.Version101 {
		t.Errorf("VersionOf(71) = %v, want Version101", v)
	}

	// Gap between v1.1 and v2.0 TO2 ranges
	for msgType := uint8(72); msgType <= 79; msgType++ {
		if v := protocol.VersionOf(msgType); v != protocol.Version101 {
			t.Errorf("VersionOf(%d) in gap = %v, want Version101 (default)", msgType, v)
		}
	}

	// First v2.0 TO2 message
	if v := protocol.VersionOf(80); v != protocol.Version200 {
		t.Errorf("VersionOf(80) = %v, want Version200", v)
	}

	// Last v2.0 TO2 message
	if v := protocol.VersionOf(91); v != protocol.Version200 {
		t.Errorf("VersionOf(91) = %v, want Version200", v)
	}

	// After v2.0 TO2 range
	if v := protocol.VersionOf(92); v != protocol.Version101 {
		t.Errorf("VersionOf(92) = %v, want Version101 (default)", v)
	}
}

// TestEncryptionBoundaryV11 verifies the exact encryption boundary for
// FDO 1.1 TO2: messages 60-64 are unencrypted, 65-71 are encrypted.
func TestEncryptionBoundaryV11(t *testing.T) {
	for msgType := uint8(60); msgType <= 64; msgType++ {
		if protocol.IsTO2Encrypted(msgType) {
			t.Errorf("IsTO2Encrypted(%d) = true, want false (pre-key-exchange v1.1)", msgType)
		}
	}
	for msgType := uint8(65); msgType <= 71; msgType++ {
		if !protocol.IsTO2Encrypted(msgType) {
			t.Errorf("IsTO2Encrypted(%d) = false, want true (post-key-exchange v1.1)", msgType)
		}
	}
}

// TestEncryptionBoundaryV20 verifies the exact encryption boundary for
// FDO 2.0 TO2: messages 80-85 are unencrypted, 86-91 are encrypted.
func TestEncryptionBoundaryV20(t *testing.T) {
	for msgType := uint8(80); msgType <= 85; msgType++ {
		if protocol.IsTO2Encrypted(msgType) {
			t.Errorf("IsTO2Encrypted(%d) = true, want false (pre-key-exchange v2.0)", msgType)
		}
	}
	for msgType := uint8(86); msgType <= 91; msgType++ {
		if !protocol.IsTO2Encrypted(msgType) {
			t.Errorf("IsTO2Encrypted(%d) = false, want true (post-key-exchange v2.0)", msgType)
		}
	}
}
