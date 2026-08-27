// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package kex_test

import (
	"testing"

	"github.com/fido-device-onboard/go-fdo/v2/kex"
)

func TestDHExchange(t *testing.T) {
	for _, suite := range []kex.Suite{kex.DHKEXid14Suite, kex.DHKEXid15Suite} {
		t.Run(string(suite), testSuite(suite))
	}
}
