// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo_test

import (
	"testing"

	"github.com/fido-device-onboard/go-fdo/fdotest"
)

func TestClient(t *testing.T) {
	fdotest.RunClientTestSuite(t, nil, nil, nil)
}

func TestServerState(t *testing.T) {
	fdotest.RunServerStateSuite(t, nil)
}
