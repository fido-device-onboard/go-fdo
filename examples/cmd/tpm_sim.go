// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

//go:build tpmsim

package main

import (
	"io"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpmutil"

	"github.com/fido-device-onboard/go-fdo/tpm"
)

func tpmOpen(tpmPath string) (tpm.Closer, error) {
	if tpmPath == "simulator" {
		sim, err := simulator.GetWithFixedSeedInsecure(8086)
		if err != nil {
			return nil, err
		}
		return &TPM{transport: sim}, nil
	}
	return tpm.Open(tpmPath)
}

// TPM represents a connection to a TPM simulator.
type TPM struct {
	transport io.ReadWriteCloser
}

// Send implements the TPM interface.
func (t *TPM) Send(input []byte) ([]byte, error) {
	return tpmutil.RunCommandRaw(t.transport, input)
}

// Close implements the TPM interface.
func (t *TPM) Close() error {
	return t.transport.Close()
}
