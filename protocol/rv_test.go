// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package protocol_test

import (
	"fmt"
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
