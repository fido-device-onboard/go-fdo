// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package serviceinfo_test

import (
	"bytes"
	"testing"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

func TestKVSize(t *testing.T) {
	for _, test := range []serviceinfo.KV{
		{Key: "", Val: nil},
		{Key: "mod:msg", Val: []byte("hello world!")},
		{Key: "modA:msgB", Val: bytes.Repeat([]byte("Hi"), 100)},
		{Key: "modA:msgB", Val: bytes.Repeat([]byte("Hi"), 1000)},
	} {
		got := int(test.Size())
		data, err := cbor.Marshal(test)
		if err != nil {
			t.Fatalf("error marshaling KV: %v", err)
		}
		expect := len(data)
		if got != expect {
			t.Errorf("expected Size to return %d, got %d", expect, got)
		}
	}
}
