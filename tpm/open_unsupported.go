// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

//go:build tinygo || (!linux && !windows && !tpmsim)

package tpm

import "fmt"

// DefaultOpen returns an error on unsupported platforms.
// Build on Linux, Windows, or with -tags=tpmsim for TPM support.
func DefaultOpen() (Closer, error) {
	return nil, fmt.Errorf("no TPM support on this platform; build with -tags=tpmsim or on Linux/Windows")
}

// ResetSimulator is a no-op on unsupported platforms.
// It exists for API compatibility with the simulator build (-tags=tpmsim).
func ResetSimulator() {}
