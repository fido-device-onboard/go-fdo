// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package kex_test

import (
	"testing"

	"github.com/fido-device-onboard/go-fdo/kex"
)

func TestDHKEXExchange(t *testing.T) {
	for _, suite := range []kex.Suite{kex.DHKEXid14Suite, kex.DHKEXid15Suite} {
		t.Run(string(suite), testSuite(suite))
	}
}
