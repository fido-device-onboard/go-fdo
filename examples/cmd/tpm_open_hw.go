// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

//go:build tpm && !tpmsim && !tinygo

package main

import (
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"

	"github.com/fido-device-onboard/go-fdo/tpm"
)

func tpmOpen(tpmPath string) (tpm.Closer, error) {
	if tpmPath == "" {
		return tpm.DefaultOpen()
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
