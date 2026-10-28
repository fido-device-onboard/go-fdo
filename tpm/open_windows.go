// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

//go:build windows && !tpmsim && !tinygo

package tpm

import "github.com/google/go-tpm/tpm2/transport/windowstpm"

// DefaultOpen opens the platform TPM via TPM Base Services (tbs.dll), which
// also provides resource management (the role of /dev/tpmrm0 on Linux).
// TBS is present on Windows and in WinPE images that include the
// WinPE-SecureStartup component (stock Windows Setup boot.wim does).
// Build with -tags=tpmsim to use the in-process software simulator instead.
func DefaultOpen() (Closer, error) {
	return windowstpm.Open()
}

// ResetSimulator is a no-op on hardware TPM builds.
// It exists for API compatibility with the simulator build (-tags=tpmsim).
func ResetSimulator() {}
