// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package kex_test

import (
	"testing"

	"github.com/fido-device-onboard/go-fdo/kex"
)

func TestOAEPExchange(t *testing.T) {
	for _, suite := range []kex.Suite{kex.ASYMKEX2048Suite, kex.ASYMKEX3072Suite} {
		t.Run(string(suite), testSuite(suite))
	}
}
