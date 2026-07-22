// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"testing"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// TestTO0CapabilityFlagsInHello verifies that the TO0 Hello message (msg 20)
// carries capability flags. The TO0 client sends GlobalCapabilityFlags which
// must include version support and delegation advertisement.
func TestTO0CapabilityFlagsInHello(t *testing.T) {
	// The TO0 Hello message body is GlobalCapabilityFlags.
	// Verify the global flags have the expected capabilities for TO0.
	flags := fdo.GlobalCapabilityFlags

	if !flags.SupportsVersion(fdo.Capb0SupFDO10) {
		t.Error("GlobalCapabilityFlags should support FDO 1.0 for TO0")
	}
	if !flags.SupportsVersion(fdo.Capb0SupFDO11) {
		t.Error("GlobalCapabilityFlags should support FDO 1.1 for TO0")
	}
	if !flags.SupportsVersion(fdo.Capb0SupFDO20) {
		t.Error("GlobalCapabilityFlags should support FDO 2.0 for TO0")
	}
	if !flags.SupportsDelegate() {
		t.Error("GlobalCapabilityFlags should support delegation for TO0")
	}

	// Verify the flags can be CBOR-encoded (as required for TO0 Hello msg)
	data, err := cbor.Marshal(flags)
	if err != nil {
		t.Fatalf("failed to marshal GlobalCapabilityFlags: %v", err)
	}
	var decoded fdo.CapabilityFlags
	if err := cbor.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal GlobalCapabilityFlags: %v", err)
	}
	if !decoded.SupportsVersion(fdo.Capb0SupFDO20) {
		t.Error("decoded flags should support FDO 2.0")
	}
	if !decoded.SupportsDelegate() {
		t.Error("decoded flags should support delegation")
	}
}

// TestTO0MessageTypes verifies that TO0 message types are correctly
// classified by the protocol package.
func TestTO0MessageTypes(t *testing.T) {
	to0Messages := []struct {
		name    string
		msgType uint8
	}{
		{"Hello", protocol.TO0HelloMsgType},
		{"HelloAck", protocol.TO0HelloAckMsgType},
		{"OwnerSign", protocol.TO0OwnerSignMsgType},
		{"AcceptOwner", protocol.TO0AcceptOwnerMsgType},
	}

	for _, msg := range to0Messages {
		t.Run(msg.name, func(t *testing.T) {
			if p := protocol.Of(msg.msgType); p != protocol.TO0Protocol {
				t.Errorf("Of(%d) = %v, want TO0Protocol", msg.msgType, p)
			}
			if v := protocol.VersionOf(msg.msgType); v != protocol.Version101 {
				t.Errorf("VersionOf(%d) = %v, want Version101 (TO0 uses 101 path)", msg.msgType, v)
			}
			if protocol.IsTO2Encrypted(msg.msgType) {
				t.Errorf("IsTO2Encrypted(%d) should be false for TO0", msg.msgType)
			}
		})
	}

	// TO0 Hello starts a protocol session
	if !protocol.IsProtocolStart(protocol.TO0HelloMsgType) {
		t.Error("TO0 Hello should be a protocol start")
	}
	// TO0 AcceptOwner ends a protocol session
	if !protocol.IsProtocolEnd(protocol.TO0AcceptOwnerMsgType) {
		t.Error("TO0 AcceptOwner should be a protocol end")
	}
}

// TestTO0WithDelegateKey verifies that TO0 can use a delegate key for
// signing the rendezvous blob instead of the owner key. This tests the
// delegate key infrastructure required for TO0 delegation.
func TestTO0WithDelegateKey(t *testing.T) {
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	delegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate delegate key: %v", err)
	}

	// Create a delegate with redirect permission (required for TO0)
	cert, err := fdo.GenerateDelegate(
		ownerKey,
		fdo.DelegateFlagRoot,
		delegateKey.Public(),
		"TO0Delegate",
		"Owner",
		[]asn1.ObjectIdentifier{fdo.OIDPermitRedirect},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate delegate cert: %v", err)
	}

	// Verify the delegate has redirect permission
	chain := []*x509.Certificate{cert}
	if !fdo.DelegateCanRedirect(chain) {
		t.Fatal("delegate should have redirect permission for TO0")
	}

	// Verify the delegate chain is valid against the owner key
	ownerPubKey := ownerKey.Public()
	if err := fdo.VerifyDelegateChain(chain, &ownerPubKey, &fdo.OIDPermitRedirect); err != nil {
		t.Fatalf("delegate chain verification failed: %v", err)
	}

	// A delegate with only onboard permission should NOT be usable for TO0
	onboardOnlyKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate onboard-only key: %v", err)
	}

	onboardCert, err := fdo.GenerateDelegate(
		ownerKey,
		fdo.DelegateFlagRoot,
		onboardOnlyKey.Public(),
		"OnboardOnlyDelegate",
		"Owner",
		[]asn1.ObjectIdentifier{fdo.OIDPermitOnboardNewCred},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate onboard-only cert: %v", err)
	}

	onboardChain := []*x509.Certificate{onboardCert}
	if fdo.DelegateCanRedirect(onboardChain) {
		t.Error("SECURITY: onboard-only delegate should NOT have redirect permission")
	}
}

// TestTO0CapabilityFlagsCBORRoundTrip verifies that CapabilityFlags can be
// marshaled and unmarshaled through CBOR, which is required for the TO0
// Hello/HelloAck messages.
func TestTO0CapabilityFlagsCBORRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		flags fdo.CapabilityFlags
	}{
		{
			name:  "empty flags",
			flags: fdo.CapabilityFlags{},
		},
		{
			name:  "FDO 2.0 only",
			flags: fdo.CapabilityFlags{Flags: []byte{fdo.Capb0SupFDO20}},
		},
		{
			name:  "all versions with delegation",
			flags: fdo.CapabilityFlags{Flags: []byte{fdo.Capb0SupFDO10 | fdo.Capb0SupFDO11 | fdo.Capb0SupFDO20 | fdo.DelegateSupportFlag}},
		},
		{
			name: "with vendor unique",
			flags: fdo.CapabilityFlags{
				Flags:        []byte{fdo.Capb0SupFDO20},
				VendorUnique: []string{"com.example.feature1"},
			},
		},
		{
			name:  "global capability flags",
			flags: fdo.GlobalCapabilityFlags,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := cbor.Marshal(tt.flags)
			if err != nil {
				t.Fatalf("marshal error: %v", err)
			}

			var decoded fdo.CapabilityFlags
			if err := cbor.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("unmarshal error: %v", err)
			}

			// Verify flag bytes match
			if !bytes.Equal(decoded.Flags, tt.flags.Flags) {
				t.Errorf("flags mismatch: got %v, want %v", decoded.Flags, tt.flags.Flags)
			}

			// Verify version support is preserved
			for _, flag := range []byte{fdo.Capb0SupFDO10, fdo.Capb0SupFDO11, fdo.Capb0SupFDO20} {
				if tt.flags.SupportsVersion(flag) != decoded.SupportsVersion(flag) {
					t.Errorf("SupportsVersion(0x%02x) mismatch after round-trip", flag)
				}
			}

			// Verify delegation support is preserved
			if tt.flags.SupportsDelegate() != decoded.SupportsDelegate() {
				t.Error("SupportsDelegate mismatch after round-trip")
			}
		})
	}
}

// TestTO0OwnerSignDelegateChainSerialization verifies that the delegate
// chain field in TO0.OwnerSign is properly handled as an optional CBOR
// field (nil when no delegation, present when delegation is used).
func TestTO0OwnerSignDelegateChainSerialization(t *testing.T) {
	t.Run("without delegate chain", func(t *testing.T) {
		// When no delegate is used, DelegateChain should be nil
		type ownerSign struct {
			To0d          []byte
			To1d          []byte
			DelegateChain *[]*cbor.X509Certificate `cbor:",omitempty"`
		}
		msg := ownerSign{
			To0d:          []byte{0x01},
			To1d:          []byte{0x02},
			DelegateChain: nil,
		}
		data, err := cbor.Marshal(msg)
		if err != nil {
			t.Fatalf("marshal error: %v", err)
		}

		var decoded ownerSign
		if err := cbor.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}
		if decoded.DelegateChain != nil {
			t.Error("DelegateChain should be nil when no delegation")
		}
	})

	t.Run("with delegate chain", func(t *testing.T) {
		ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate owner key: %v", err)
		}
		delegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate delegate key: %v", err)
		}

		cert, err := fdo.GenerateDelegate(
			ownerKey,
			fdo.DelegateFlagRoot,
			delegateKey.Public(),
			"Delegate",
			"Owner",
			[]asn1.ObjectIdentifier{fdo.OIDPermitRedirect},
			x509.ECDSAWithSHA384,
		)
		if err != nil {
			t.Fatalf("failed to generate delegate cert: %v", err)
		}

		cbCert := (*cbor.X509Certificate)(cert)
		chain := []*cbor.X509Certificate{cbCert}

		type ownerSign struct {
			To0d          []byte
			To1d          []byte
			DelegateChain *[]*cbor.X509Certificate `cbor:",omitempty"`
		}
		msg := ownerSign{
			To0d:          []byte{0x01},
			To1d:          []byte{0x02},
			DelegateChain: &chain,
		}
		data, err := cbor.Marshal(msg)
		if err != nil {
			t.Fatalf("marshal error: %v", err)
		}

		var decoded ownerSign
		if err := cbor.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}
		if decoded.DelegateChain == nil {
			t.Fatal("DelegateChain should not be nil when delegation is used")
		}
		if len(*decoded.DelegateChain) != 1 {
			t.Fatalf("expected 1 cert in delegate chain, got %d", len(*decoded.DelegateChain))
		}
	})
}
