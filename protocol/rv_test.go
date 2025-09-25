// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package protocol_test

import (
	"fmt"
	"net"
	"reflect"
	"testing"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

func TestParseExternal(t *testing.T) {
	for _, expectArguments := range [][]any{
		{},
		{int64(3)},
		{int64(3), "1415926"},
	} {
		t.Run(fmt.Sprintf("%d args", len(expectArguments)), func(t *testing.T) {
			expectMechanism := "use_ai"

			extValue, err := cbor.Marshal(append([]any{expectMechanism}, expectArguments...))
			if err != nil {
				t.Fatal(err)
			}
			directives := protocol.ParseDeviceRvInfo([][]protocol.RvInstruction{
				{
					{
						Variable: protocol.RVExtRV,
						Value:    extValue,
					},
				},
			})
			if n := len(directives); n != 1 {
				t.Fatalf("expected one directive, got %d", n)
			}
			if got := directives[0].ExtMechanism; expectMechanism != got {
				t.Fatalf("expected %q mechanism, got %q", expectMechanism, got)
			}
			var got []any
			if err := cbor.Unmarshal(directives[0].ExtArguments, &got); err != nil {
				t.Fatalf("error parsing arguments: %v", err)
			}
			if !reflect.DeepEqual(expectArguments, got) {
				t.Fatalf("expected %#v arguments, got %#v", expectArguments, got)
			}
		})
	}
}

func TestPortBeforeProtocol(t *testing.T) {
	// Test that setting port first, then protocol, preserves the explicit port
	// instead of overwriting it with the protocol's default port

	t.Run("DevicePort", func(t *testing.T) {
		// Set DevPort to 8080 followed by RVProtHTTP
		instructions := []protocol.RvInstruction{
			{Variable: protocol.RVDevPort, Value: mustMarshal(t, uint16(8080))},
			{Variable: protocol.RVProtocol, Value: mustMarshal(t, protocol.RVProtHTTP)},
			{Variable: protocol.RVIPAddress, Value: mustMarshal(t, net.IP{127, 0, 0, 1})},
		}

		directives := protocol.ParseDeviceRvInfo([][]protocol.RvInstruction{instructions})
		if len(directives) != 1 {
			t.Fatalf("expected 1 directive, got %d", len(directives))
		}

		urls := directives[0].URLs
		if len(urls) != 1 {
			t.Fatalf("expected 1 URL, got %d", len(urls))
		}

		if urls[0].Scheme != "http" {
			t.Errorf("expected scheme 'http', got %q", urls[0].Scheme)
		}

		if port := urls[0].Port(); port != "8080" {
			t.Errorf("expected port '8080', got %q", port)
		}
	})

	t.Run("OwnerPort", func(t *testing.T) {
		// Set OwnerPort to 8080 followed by RVProtHTTP
		instructions := []protocol.RvInstruction{
			{Variable: protocol.RVOwnerPort, Value: mustMarshal(t, uint16(8080))},
			{Variable: protocol.RVProtocol, Value: mustMarshal(t, protocol.RVProtHTTP)},
			{Variable: protocol.RVIPAddress, Value: mustMarshal(t, net.IP{127, 0, 0, 1})},
		}

		directives := protocol.ParseOwnerRvInfo([][]protocol.RvInstruction{instructions})
		if len(directives) != 1 {
			t.Fatalf("expected 1 directive, got %d", len(directives))
		}

		urls := directives[0].URLs
		if len(urls) != 1 {
			t.Fatalf("expected 1 URL, got %d", len(urls))
		}

		if urls[0].Scheme != "http" {
			t.Errorf("expected scheme 'http', got %q", urls[0].Scheme)
		}

		if port := urls[0].Port(); port != "8080" {
			t.Errorf("expected port '8080', got %q", port)
		}
	})

	t.Run("DefaultPortWhenNotExplicit", func(t *testing.T) {
		// Verify that default port is still used when no explicit port is set
		instructions := []protocol.RvInstruction{
			{Variable: protocol.RVProtocol, Value: mustMarshal(t, protocol.RVProtHTTP)},
			{Variable: protocol.RVIPAddress, Value: mustMarshal(t, net.IP{127, 0, 0, 1})},
		}

		directives := protocol.ParseDeviceRvInfo([][]protocol.RvInstruction{instructions})
		if len(directives) != 1 {
			t.Fatalf("expected 1 directive, got %d", len(directives))
		}

		urls := directives[0].URLs
		if len(urls) != 1 {
			t.Fatalf("expected 1 URL, got %d", len(urls))
		}

		if port := urls[0].Port(); port != "80" {
			t.Errorf("expected default port '80', got %q", port)
		}
	})
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	data, err := cbor.Marshal(v)
	if err != nil {
		t.Fatalf("error marshaling %v: %v", v, err)
	}
	return data
}
