// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

//go:build !tpmsim

package main

import (
	"fmt"

	"github.com/google/go-tpm/tpm2/transport/linuxtpm"

	"github.com/fido-device-onboard/go-fdo/tpm"
)

func tpmOpen(tpmPath string) (tpm.Closer, error) {
	if tpmPath == "simulator" {
		return nil, fmt.Errorf("tpm simulator support requires a build with the tpmsim tag")
	}
	return linuxtpm.Open(tpmPath)
}
