// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

//go:build tpmsim

package main

import (
	"github.com/google/go-tpm/tpm2/transport/simulator"

	"github.com/fido-device-onboard/go-fdo/tpm"
)

func tpmOpen(tpmPath string) (tpm.Closer, error) {
	if tpmPath == "simulator" {
		return simulator.OpenSimulator()
	}
	return tpm.Open(tpmPath)
}
