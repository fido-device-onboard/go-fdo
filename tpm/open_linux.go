// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

//go:build linux && !tpmsim && !tinygo

package tpm

import (
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"
)

// DefaultOpen opens the platform TPM via the kernel resource manager.
// If the FDO_TPM_DEVICE environment variable is set, it uses that path
// instead, automatically detecting Unix sockets (for swtpm) vs character
// devices (for hardware TPM).
// Build with -tags=tpmsim to use the in-process software simulator instead.
func DefaultOpen() (Closer, error) {
	path := os.Getenv("FDO_TPM_DEVICE")
	if path == "" {
		path = "/dev/tpmrm0"
	}
	return openTPMPath(path)
}

// openTPMPath opens a TPM at the given path, auto-detecting Unix sockets
// (swtpm) vs character devices (hardware TPM).
func openTPMPath(path string) (Closer, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("opening TPM device %s: %w", path, err)
	}
	if fi.Mode()&os.ModeSocket != 0 {
		return linuxudstpm.Open(path)
	}
	return linuxtpm.Open(path)
}

// ResetSimulator is a no-op on hardware TPM builds.
// It exists for API compatibility with the simulator build (-tags=tpmsim).
func ResetSimulator() {}
