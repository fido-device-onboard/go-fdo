// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

//go:build tpmsim && !tinygo

package tpm

import (
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

// DefaultOpen opens a TPM software simulator.
// This build was compiled with -tags=tpmsim; it requires CGO.
func DefaultOpen() (Closer, error) {
	return simulator.OpenSimulator()
}
