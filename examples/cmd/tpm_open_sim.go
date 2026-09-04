// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

//go:build tpmsim && !tinygo

package main

import (
	"fmt"
	"os"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"

	"github.com/fido-device-onboard/go-fdo/tpm"
)

const tpmSimulatorPath = "simulator"

func tpmOpen(tpmPath string) (tpm.Closer, error) {
	if tpmPath == "" {
		return tpm.DefaultOpen()
	}
	if tpmPath == tpmSimulatorPath {
		sim, err := simulator.GetWithFixedSeedInsecure(8086)
		if err != nil {
			return nil, err
		}
		return transport.FromReadWriteCloser(sim), nil
	}
	// Auto-detect Unix socket (swtpm) vs character device (hardware TPM)
	fi, err := os.Stat(tpmPath)
	if err != nil {
		return nil, fmt.Errorf("opening TPM at %s: %w", tpmPath, err)
	}
	if fi.Mode()&os.ModeSocket != 0 {
		return linuxudstpm.Open(tpmPath)
	}
	return linuxtpm.Open(tpmPath)
}
