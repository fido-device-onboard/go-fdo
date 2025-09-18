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

func cborMarshal(t *testing.T, v any) []byte {
	t.Helper()

	b, err := cbor.Marshal(v)
	if err != nil {
		t.Fatalf("failed to marshal CBOR: %v", err)
	}
	return b
}

func TestParseURL(t *testing.T) {
	testCases := []struct {
		name         string
		instructions []protocol.RvInstruction
		expectURLs   []string
	}{
		{
			name: "DNS only",
			instructions: []protocol.RvInstruction{
				{Variable: protocol.RVProtocol, Value: cborMarshal(t, protocol.RVProtHTTPS)},
				{Variable: protocol.RVDns, Value: cborMarshal(t, "example.com")},
			},
			expectURLs: []string{"https://example.com:443"},
		},
		{
			name: "IP only",
			instructions: []protocol.RvInstruction{
				{Variable: protocol.RVProtocol, Value: cborMarshal(t, protocol.RVProtHTTPS)},
				{Variable: protocol.RVIPAddress, Value: cborMarshal(t, net.ParseIP("192.0.2.1"))},
			},
			expectURLs: []string{"https://192.0.2.1:443"},
		},
		{
			name: "IPv6 only",
			instructions: []protocol.RvInstruction{
				{Variable: protocol.RVProtocol, Value: cborMarshal(t, protocol.RVProtHTTPS)},
				{Variable: protocol.RVIPAddress, Value: cborMarshal(t, net.ParseIP("2001:db8::1"))},
			},
			expectURLs: []string{"https://[2001:db8::1]:443"},
		},
		{
			name: "DNS and Port",
			instructions: []protocol.RvInstruction{
				{Variable: protocol.RVProtocol, Value: cborMarshal(t, protocol.RVProtHTTPS)},
				{Variable: protocol.RVDns, Value: cborMarshal(t, "example.com")},
				{Variable: protocol.RVDevPort, Value: cborMarshal(t, 8080)},
			},
			expectURLs: []string{"https://example.com:8080"},
		},
		{
			name: "IP and Port",
			instructions: []protocol.RvInstruction{
				{Variable: protocol.RVProtocol, Value: cborMarshal(t, protocol.RVProtHTTPS)},
				{Variable: protocol.RVIPAddress, Value: cborMarshal(t, net.ParseIP("192.0.2.1"))},
				{Variable: protocol.RVDevPort, Value: cborMarshal(t, 8080)},
			},
			expectURLs: []string{"https://192.0.2.1:8080"},
		},
		{
			name: "DNS and HTTP protocol",
			instructions: []protocol.RvInstruction{
				{Variable: protocol.RVProtocol, Value: cborMarshal(t, protocol.RVProtHTTP)},
				{Variable: protocol.RVDns, Value: cborMarshal(t, "example.com")},
			},
			expectURLs: []string{"http://example.com:80"},
		},
		{
			name: "DNS, HTTP protocol, default port",
			instructions: []protocol.RvInstruction{
				{Variable: protocol.RVProtocol, Value: cborMarshal(t, protocol.RVProtHTTP)},
				{Variable: protocol.RVDns, Value: cborMarshal(t, "example.com")},
				{Variable: protocol.RVDevPort, Value: cborMarshal(t, 80)},
			},
			expectURLs: []string{"http://example.com:80"},
		},
		{
			name: "DNS, HTTP protocol, custom port",
			instructions: []protocol.RvInstruction{
				{Variable: protocol.RVProtocol, Value: cborMarshal(t, protocol.RVProtHTTP)},
				{Variable: protocol.RVDns, Value: cborMarshal(t, "example.com")},
				{Variable: protocol.RVDevPort, Value: cborMarshal(t, 8080)},
			},
			expectURLs: []string{"http://example.com:8080"},
		},
		{
			name: "DNS and IP",
			instructions: []protocol.RvInstruction{
				{Variable: protocol.RVProtocol, Value: cborMarshal(t, protocol.RVProtHTTPS)},
				{Variable: protocol.RVDns, Value: cborMarshal(t, "example.com")},
				{Variable: protocol.RVIPAddress, Value: cborMarshal(t, net.ParseIP("192.0.2.1"))},
			},
			expectURLs: []string{"https://example.com:443", "https://192.0.2.1:443"},
		},
		{
			name: "Protocol after port",
			instructions: []protocol.RvInstruction{
				{Variable: protocol.RVDns, Value: cborMarshal(t, "example.com")},
				{Variable: protocol.RVDevPort, Value: cborMarshal(t, 8080)},
				{Variable: protocol.RVProtocol, Value: cborMarshal(t, protocol.RVProtHTTPS)},
			},
			expectURLs: []string{"https://example.com:8080"},
		},
		{
			name: "No host",
			instructions: []protocol.RvInstruction{
				{Variable: protocol.RVDevPort, Value: cborMarshal(t, 8080)},
				{Variable: protocol.RVProtocol, Value: cborMarshal(t, protocol.RVProtHTTP)},
			},
			expectURLs: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			directives := protocol.ParseDeviceRvInfo([][]protocol.RvInstruction{tc.instructions})
			if n := len(directives); n != 1 {
				t.Fatalf("expected one directive, got %d", n)
			}
			directive := directives[0]

			var urls []string
			for _, u := range directive.URLs {
				urls = append(urls, u.String())
			}

			if !reflect.DeepEqual(tc.expectURLs, urls) {
				t.Fatalf("expected URLs %v, got %v", tc.expectURLs, urls)
			}
		})
	}
}
