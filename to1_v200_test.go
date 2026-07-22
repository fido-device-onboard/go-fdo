// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo_test

import (
	"testing"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// TestTO1CapabilityFlagsInHelloRV verifies that the TO1 HelloRV message
// (msg 30) carries capability flags. The device sends GlobalCapabilityFlags
// as part of the TO1 HelloRV message to advertise its version support and
// feature capabilities to the Rendezvous Server.
func TestTO1CapabilityFlagsInHelloRV(t *testing.T) {
	// Verify GlobalCapabilityFlags for TO1 context
	flags := fdo.GlobalCapabilityFlags

	if !flags.SupportsVersion(fdo.Capb0SupFDO20) {
		t.Error("GlobalCapabilityFlags should support FDO 2.0 for TO1")
	}
	if !flags.SupportsVersion(fdo.Capb0SupFDO11) {
		t.Error("GlobalCapabilityFlags should support FDO 1.1 for TO1")
	}
	if !flags.SupportsDelegate() {
		t.Error("GlobalCapabilityFlags should support delegation for TO1")
	}
}

// TestTO1MessageTypes verifies that TO1 message types are correctly
// classified by the protocol package.
func TestTO1MessageTypes(t *testing.T) {
	to1Messages := []struct {
		name    string
		msgType uint8
	}{
		{"HelloRV", protocol.TO1HelloRVMsgType},
		{"HelloRVAck", protocol.TO1HelloRVAckMsgType},
		{"ProveToRV", protocol.TO1ProveToRVMsgType},
		{"RVRedirect", protocol.TO1RVRedirectMsgType},
	}

	for _, msg := range to1Messages {
		t.Run(msg.name, func(t *testing.T) {
			if p := protocol.Of(msg.msgType); p != protocol.TO1Protocol {
				t.Errorf("Of(%d) = %v, want TO1Protocol", msg.msgType, p)
			}
			if v := protocol.VersionOf(msg.msgType); v != protocol.Version101 {
				t.Errorf("VersionOf(%d) = %v, want Version101 (TO1 uses 101 path)", msg.msgType, v)
			}
			if protocol.IsTO2Encrypted(msg.msgType) {
				t.Errorf("IsTO2Encrypted(%d) should be false for TO1", msg.msgType)
			}
		})
	}

	// TO1 HelloRV starts a protocol session
	if !protocol.IsProtocolStart(protocol.TO1HelloRVMsgType) {
		t.Error("TO1 HelloRV should be a protocol start")
	}
	// TO1 RVRedirect ends a protocol session
	if !protocol.IsProtocolEnd(protocol.TO1RVRedirectMsgType) {
		t.Error("TO1 RVRedirect should be a protocol end")
	}
}

// TestTO1HelloRVStructure verifies the structure of the TO1 HelloRV message
// matches the FDO 2.0 specification: [GUID, ASigInfo, CapFlags].
func TestTO1HelloRVStructure(t *testing.T) {
	// The HelloRV struct is internal, but we can verify that
	// CapabilityFlags can be encoded as part of a CBOR array alongside
	// the other HelloRV fields.
	type helloRV struct {
		GUID     protocol.GUID
		ASigInfo struct {
			SigInfoType int
			Info        []byte
		}
		CapFlags fdo.CapabilityFlags `cbor:",omitempty"`
	}

	msg := helloRV{
		GUID: protocol.GUID{0x01, 0x02, 0x03},
		ASigInfo: struct {
			SigInfoType int
			Info        []byte
		}{
			SigInfoType: -7, // ES256
			Info:        []byte{},
		},
		CapFlags: fdo.GlobalCapabilityFlags,
	}

	data, err := cbor.Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal HelloRV: %v", err)
	}

	var decoded helloRV
	if err := cbor.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal HelloRV: %v", err)
	}

	if decoded.GUID != msg.GUID {
		t.Errorf("GUID mismatch: got %v, want %v", decoded.GUID, msg.GUID)
	}
	if !decoded.CapFlags.SupportsVersion(fdo.Capb0SupFDO20) {
		t.Error("decoded CapFlags should support FDO 2.0")
	}
}

// TestTO1HelloRVAckStructure verifies the structure of the TO1 HelloRVAck
// message: [NonceTO1Proof, BSigInfo, CapFlags].
func TestTO1HelloRVAckStructure(t *testing.T) {
	type rvAck struct {
		NonceTO1Proof protocol.Nonce
		BSigInfo      struct {
			SigInfoType int
			Info        []byte
		}
		CapFlags fdo.CapabilityFlags `cbor:",omitempty"`
	}

	var nonce protocol.Nonce
	copy(nonce[:], []byte{0xAA, 0xBB, 0xCC, 0xDD})

	msg := rvAck{
		NonceTO1Proof: nonce,
		BSigInfo: struct {
			SigInfoType int
			Info        []byte
		}{
			SigInfoType: -7, // ES256
			Info:        []byte{},
		},
		CapFlags: fdo.GlobalCapabilityFlags,
	}

	data, err := cbor.Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal HelloRVAck: %v", err)
	}

	var decoded rvAck
	if err := cbor.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal HelloRVAck: %v", err)
	}

	if decoded.NonceTO1Proof != msg.NonceTO1Proof {
		t.Errorf("nonce mismatch: got %v, want %v", decoded.NonceTO1Proof, msg.NonceTO1Proof)
	}
	if !decoded.CapFlags.SupportsVersion(fdo.Capb0SupFDO20) {
		t.Error("decoded CapFlags should support FDO 2.0")
	}
	if !decoded.CapFlags.SupportsDelegate() {
		t.Error("decoded CapFlags should support delegation")
	}
}

// TestTO1CapabilityFlagsNilSafety verifies that CapabilityFlags methods
// handle nil and zero-length flag slices gracefully. This is important
// for backwards compatibility with FDO 1.1 implementations that may not
// include capability flags.
func TestTO1CapabilityFlagsNilSafety(t *testing.T) {
	t.Run("nil flags", func(t *testing.T) {
		var f *fdo.CapabilityFlags
		if f.SupportsVersion(fdo.Capb0SupFDO20) {
			t.Error("nil flags should not support any version")
		}
		if f.SupportsDelegate() {
			t.Error("nil flags should not support delegation")
		}
	})

	t.Run("empty flags", func(t *testing.T) {
		f := &fdo.CapabilityFlags{Flags: []byte{}}
		if f.SupportsVersion(fdo.Capb0SupFDO20) {
			t.Error("empty flags should not support any version")
		}
		if f.SupportsDelegate() {
			t.Error("empty flags should not support delegation")
		}
	})

	t.Run("nil flags struct", func(t *testing.T) {
		f := &fdo.CapabilityFlags{}
		if f.SupportsVersion(fdo.Capb0SupFDO20) {
			t.Error("zero-value flags should not support any version")
		}
		if f.SupportsDelegate() {
			t.Error("zero-value flags should not support delegation")
		}
	})
}
