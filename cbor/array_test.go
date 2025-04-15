// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cbor_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

func TestArrayShift(t *testing.T) {
	t.Run("invalid input", func(t *testing.T) {
		for _, data := range [][]byte{
			{0x81},
			{0x64, 0x49, 0x45, 0x54, 0x46},
			{0x45, 0x48, 0x65, 0x6c, 0x6c, 0x6f},
		} {
			first, remaining := cbor.ArrayShift(data)
			if first != nil || !bytes.Equal(remaining, data) {
				t.Errorf("expected ArrayShift to fail: % x", data)
			}
		}
	})

	t.Run("without trailing data", func(t *testing.T) {
		for _, test := range []struct {
			Data   []byte
			First  []byte
			Remain []byte
		}{
			{
				Data:   []byte{0x80},
				First:  []byte{},
				Remain: []byte{0x80},
			},
			{
				Data:   []byte{0x81, 0x64, 0x49, 0x45, 0x54, 0x46},
				First:  []byte{0x64, 0x49, 0x45, 0x54, 0x46},
				Remain: []byte{0x80},
			},
			{
				Data:   []byte{0x82, 0x45, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x64, 0x49, 0x45, 0x54, 0x46},
				First:  []byte{0x45, 0x48, 0x65, 0x6c, 0x6c, 0x6f},
				Remain: []byte{0x81, 0x64, 0x49, 0x45, 0x54, 0x46},
			},
		} {
			t.Run(hex.EncodeToString(test.Data), func(t *testing.T) {
				first, remaining := cbor.ArrayShift(test.Data)
				if !bytes.Equal(test.First, first) {
					t.Errorf("first: expected % x, got % x", test.First, first)
				}
				if !bytes.Equal(test.Remain, remaining) {
					t.Errorf("remaining: expected % x, got % x", test.Remain, remaining)
				}
			})
		}
	})

	t.Run("with trailing data", func(t *testing.T) {
		for _, test := range []struct {
			Data   []byte
			First  []byte
			Remain []byte
		}{
			{
				Data:   []byte{0x80, 0x81, 0x20},
				First:  []byte{},
				Remain: []byte{0x80, 0x81, 0x20},
			},
			{
				Data:   []byte{0x81, 0x64, 0x49, 0x45, 0x54, 0x46, 0x01},
				First:  []byte{0x64, 0x49, 0x45, 0x54, 0x46},
				Remain: []byte{0x80, 0x01},
			},
			{
				Data: []byte{0x82, 0x45, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x64, 0x49, 0x45, 0x54, 0x46,
					0x81, 0x64, 0x49, 0x45, 0x54, 0x46,
				},
				First: []byte{0x45, 0x48, 0x65, 0x6c, 0x6c, 0x6f},
				Remain: []byte{
					0x81, 0x64, 0x49, 0x45, 0x54, 0x46,
					0x81, 0x64, 0x49, 0x45, 0x54, 0x46,
				},
			},
		} {
			t.Run(hex.EncodeToString(test.Data), func(t *testing.T) {
				first, remaining := cbor.ArrayShift(test.Data)
				if !bytes.Equal(test.First, first) {
					t.Errorf("first: expected % x, got % x", test.First, first)
				}
				if !bytes.Equal(test.Remain, remaining) {
					t.Errorf("remaining: expected % x, got % x", test.Remain, remaining)
				}
			})
		}
	})
}
