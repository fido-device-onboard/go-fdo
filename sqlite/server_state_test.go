// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package sqlite_test

import (
	"testing"

	"github.com/fido-device-onboard/go-fdo/fdotest"
)

func TestServerState(t *testing.T) {
	state, cleanup := newDB(t)
	defer func() { _ = cleanup() }()
	fdotest.TestServerState(state, t)
}
