// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

//go:build linux && !tpmsim && !tinygo

package tpm

import "github.com/google/go-tpm/tpm2/transport/linuxtpm"

// DefaultOpen opens the platform TPM via the kernel resource manager.
// Build with -tags=tpmsim to use the software simulator instead.
func DefaultOpen() (Closer, error) {
	return linuxtpm.Open("/dev/tpmrm0")
}
