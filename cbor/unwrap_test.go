// SPDX-FileCopyrightText: (C) 2026 Flavien Solt
// SPDX-License-Identifier: Apache 2.0

package cbor_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

func TestUnwrapLengthLimit(t *testing.T) {
	maxLength := ^uint64(0)
	wantErr := fmt.Sprintf("length exceeds max size: %d", maxLength)

	for _, test := range []struct {
		name   string
		head   byte
		unwrap func(*cbor.Decoder) (uint64, error)
	}{
		{name: "array", head: 0x9b, unwrap: (*cbor.Decoder).UnwrapArray},
		{name: "bytes", head: 0x5b, unwrap: (*cbor.Decoder).UnwrapBytes},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := append([]byte{test.head}, bytes.Repeat([]byte{0xff}, 8)...)
			length, err := test.unwrap(cbor.NewDecoder(bytes.NewReader(data)))
			if err == nil || err.Error() != wantErr {
				t.Fatalf("length=%d err=%v, want length=0 err=%q", length, err, wantErr)
			}
			if length != 0 {
				t.Fatalf("length=%d, want 0", length)
			}
		})
	}
}
