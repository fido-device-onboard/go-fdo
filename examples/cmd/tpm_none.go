// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

//go:build !tpm && !tpmsim && !tinygo

package main

import "fmt"

func tpmClearCredentials() error { return fmt.Errorf("TPM support not compiled (build with -tags=tpm or -tags=tpmsim)") }
func tpmShowCredentials() error  { return fmt.Errorf("TPM support not compiled (build with -tags=tpm or -tags=tpmsim)") }
func tpmExportDAK() error        { return fmt.Errorf("TPM support not compiled (build with -tags=tpm or -tags=tpmsim)") }
func tpmProveDAK() error         { return fmt.Errorf("TPM support not compiled (build with -tags=tpm or -tags=tpmsim)") }
