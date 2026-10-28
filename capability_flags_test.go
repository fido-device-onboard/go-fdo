// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"bytes"
	"testing"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// TestCapabilityFlagsWireLayout checks that every FDO 2.0 message carrying
// capability flags encodes them per the spec CDDL: CapabilityFlags (bstr) and
// VendorCapFlags ([* tstr]) as the first two top-level array elements, with
// the remaining fields following in spec order.
func TestCapabilityFlagsWireLayout(t *testing.T) {
	caps := CapabilityFlags{Flags: []byte{Capb0SupFDO20}}
	guid := protocol.GUID{1, 2, 3}
	nonce := protocol.Nonce{4, 5, 6}

	for _, tc := range []struct {
		name   string
		msg    any
		fields int // total top-level array elements per spec
	}{
		{"DI.AppStart", struct {
			CapabilityFlags
			Info *cbor.Bstr[any]
		}{caps, cbor.NewBstr[any]("info")}, 3},
		{"DI.SetCredentials", setCredentialsMsg20{CapabilityFlags: caps, OVHeader: *cbor.NewBstr(VoucherHeader{})}, 3},
		{"TO0.Hello", caps, 2},
		{"TO0.OwnerSign", ownerSign20{CapabilityFlags: caps}, 4},
		{"TO0.HelloAck", to0Ack20{caps, nonce}, 3},
		{"TO1.HelloRV", helloRV20{caps, guid}, 3},
		{"TO1.HelloRVAck", rvAck20{caps, nonce}, 3},
		{"TO2.HelloDeviceProbe", HelloDeviceProbeMsg{CapabilityFlags: caps, GUID: guid}, 6},
		{"TO2.HelloDeviceAck20", HelloDeviceAck20Msg{CapabilityFlags: caps, GUID: guid}, 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := cbor.Marshal(tc.msg)
			if err != nil {
				t.Fatal(err)
			}
			var elems []cbor.RawBytes
			if err := cbor.Unmarshal(b, &elems); err != nil {
				t.Fatalf("not a CBOR array: %v", err)
			}
			if len(elems) != tc.fields {
				t.Fatalf("got %d top-level elements, want %d", len(elems), tc.fields)
			}
			var flags []byte
			if err := cbor.Unmarshal(elems[0], &flags); err != nil || !bytes.Equal(flags, caps.Flags) {
				t.Errorf("element 0 is not CapabilityFlags bstr: %x (%v)", []byte(elems[0]), err)
			}
			var vendor []string
			if err := cbor.Unmarshal(elems[1], &vendor); err != nil {
				t.Errorf("element 1 is not VendorCapFlags array: %x (%v)", []byte(elems[1]), err)
			}
		})
	}
}

// TestGlobalCapabilityFlags checks the advertised versions (no FDO 1.0) and
// that an emptied vendor flag list still encodes as a CBOR array.
func TestGlobalCapabilityFlags(t *testing.T) {
	if got := GlobalCapabilityFlags.Flags[0]; got != Capb0SupFDO11|Capb0SupFDO20|DelegateSupportFlag {
		t.Errorf("flags byte 0 = %#x, want SupFDO11|SupFDO20|DELEG (%#x)", got, Capb0SupFDO11|Capb0SupFDO20|DelegateSupportFlag)
	}
	b, err := cbor.Marshal(CapabilityFlags{Flags: GlobalCapabilityFlags.Flags, VendorUnique: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	var elems []cbor.RawBytes
	if err := cbor.Unmarshal(b, &elems); err != nil || len(elems) != 2 {
		t.Fatalf("expected a 2-element array: %x (%v)", b, err)
	}
	if !bytes.Equal(elems[1], []byte{0x80}) {
		t.Errorf("empty VendorCapFlags encoded as %x, want an empty array (80)", []byte(elems[1]))
	}
}
