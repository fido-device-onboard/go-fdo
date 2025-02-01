// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

//go:build tpmsim

package main

import (
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"

	"github.com/fido-device-onboard/go-fdo/tpm"
)

func tpmOpen(tpmPath string) (tpm.Closer, error) {
	if tpmPath == "simulator" {
		sim, err := simulator.GetWithFixedSeedInsecure(8086)
		if err != nil {
			return nil, err
		}
		return transport.FromReadWriteCloser(sim), nil
	}
	return linuxtpm.Open(tpmPath)
}
