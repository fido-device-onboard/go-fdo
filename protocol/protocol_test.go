// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package protocol_test

import (
	"context"
	"testing"

	"github.com/fido-device-onboard/go-fdo/v2/protocol"
)

func TestOf(t *testing.T) {
	tests := []struct {
		msgType  uint8
		expected protocol.Protocol
	}{
		{10, protocol.DIProtocol},
		{13, protocol.DIProtocol},
		{20, protocol.TO0Protocol},
		{23, protocol.TO0Protocol},
		{30, protocol.TO1Protocol},
		{33, protocol.TO1Protocol},
		{60, protocol.TO2Protocol},
		{71, protocol.TO2Protocol},
		{80, protocol.TO2Protocol},
		{91, protocol.TO2Protocol},
		{255, protocol.AnyProtocol},
		{0, protocol.UnknownProtocol},
		{50, protocol.UnknownProtocol},
		{100, protocol.UnknownProtocol},
	}
	for _, tt := range tests {
		got := protocol.Of(tt.msgType)
		if got != tt.expected {
			t.Errorf("Of(%d) = %v, want %v", tt.msgType, got, tt.expected)
		}
	}
}

func TestVersionOf(t *testing.T) {
	tests := []struct {
		msgType  uint8
		expected protocol.Version
	}{
		{10, protocol.Version101},
		{20, protocol.Version101},
		{30, protocol.Version101},
		{60, protocol.Version101},
		{71, protocol.Version101},
		{80, protocol.Version200},
		{85, protocol.Version200},
		{91, protocol.Version200},
		{0, protocol.Version101},
		{255, protocol.Version101},
	}
	for _, tt := range tests {
		got := protocol.VersionOf(tt.msgType)
		if got != tt.expected {
			t.Errorf("VersionOf(%d) = %v, want %v", tt.msgType, got, tt.expected)
		}
	}
}

func TestIsTO2Encrypted(t *testing.T) {
	tests := []struct {
		msgType  uint8
		expected bool
	}{
		// FDO 1.1 encrypted range: 65-71
		{64, false},
		{65, true},
		{71, true},
		{72, false},
		// FDO 2.0 encrypted range: 86-91
		{85, false},
		{86, true},
		{91, true},
		{92, false},
		// Other message types
		{10, false},
		{80, false},
	}
	for _, tt := range tests {
		got := protocol.IsTO2Encrypted(tt.msgType)
		if got != tt.expected {
			t.Errorf("IsTO2Encrypted(%d) = %v, want %v", tt.msgType, got, tt.expected)
		}
	}
}

func TestIsProtocolStart(t *testing.T) {
	starts := []uint8{10, 20, 30, 60, 80}
	for _, msgType := range starts {
		if !protocol.IsProtocolStart(msgType) {
			t.Errorf("IsProtocolStart(%d) = false, want true", msgType)
		}
	}
	nonStarts := []uint8{11, 21, 31, 61, 81, 0, 255}
	for _, msgType := range nonStarts {
		if protocol.IsProtocolStart(msgType) {
			t.Errorf("IsProtocolStart(%d) = true, want false", msgType)
		}
	}
}

func TestIsProtocolEnd(t *testing.T) {
	ends := []uint8{13, 23, 33, 71, 91}
	for _, respType := range ends {
		if !protocol.IsProtocolEnd(respType) {
			t.Errorf("IsProtocolEnd(%d) = false, want true", respType)
		}
	}
	nonEnds := []uint8{10, 20, 30, 60, 80, 90, 0, 255}
	for _, respType := range nonEnds {
		if protocol.IsProtocolEnd(respType) {
			t.Errorf("IsProtocolEnd(%d) = true, want false", respType)
		}
	}
}

func TestVersionString(t *testing.T) {
	if protocol.Version101.String() != "101" {
		t.Errorf("Version101.String() = %q, want %q", protocol.Version101.String(), "101")
	}
	if protocol.Version200.String() != "200" {
		t.Errorf("Version200.String() = %q, want %q", protocol.Version200.String(), "200")
	}
	if protocol.Version(999).String() != "unknown" {
		t.Errorf("Version(999).String() = %q, want %q", protocol.Version(999).String(), "unknown")
	}
}

func TestVersionIsValid(t *testing.T) {
	if !protocol.Version101.IsValid() {
		t.Error("Version101.IsValid() = false, want true")
	}
	if !protocol.Version200.IsValid() {
		t.Error("Version200.IsValid() = false, want true")
	}
	if protocol.Version(999).IsValid() {
		t.Error("Version(999).IsValid() = true, want false")
	}
}

func TestVersionContext(t *testing.T) {
	ctx := context.Background()
	if v := protocol.VersionFromContext(ctx); v != protocol.Version101 {
		t.Errorf("VersionFromContext(empty) = %v, want %v", v, protocol.Version101)
	}

	ctx = protocol.ContextWithVersion(ctx, protocol.Version200)
	if v := protocol.VersionFromContext(ctx); v != protocol.Version200 {
		t.Errorf("VersionFromContext(v200) = %v, want %v", v, protocol.Version200)
	}

	ctx = protocol.ContextWithVersion(ctx, protocol.Version101)
	if v := protocol.VersionFromContext(ctx); v != protocol.Version101 {
		t.Errorf("VersionFromContext(overwritten) = %v, want %v", v, protocol.Version101)
	}
}
