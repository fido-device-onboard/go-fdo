// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package tpm_test

import (
	"testing"

	"github.com/google/go-tpm/tpm2/transport/simulator"

	"github.com/fido-device-onboard/go-fdo/fdotest"
)

func TestTPMDevice(t *testing.T) {
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("error opening opening TPM simulator: %v", err)
	}
	defer func() {
		if err := sim.Close(); err != nil {
			t.Error(err)
		}
	}()

	fdotest.RunClientTestSuite(t, nil, sim, nil, nil, nil)
}
