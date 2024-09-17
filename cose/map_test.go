// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cose

import (
	"testing"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

func TestEmptyOrSerializedMap(t *testing.T) {
	var m emptyOrSerializedMap
	if err := cbor.Unmarshal([]byte{0x40}, &m); err != nil {
		t.Fatal(err)
	}
}
