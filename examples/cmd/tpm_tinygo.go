// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

//go:build tinygo

package main

import (
	"crypto"
	"hash"
)

func tpmCred() (hash.Hash, hash.Hash, crypto.Signer, func() error, error) {
	panic("TPM unsupported by TinyGo")
}

func tpmShowCredentials() error     { panic("TPM unsupported by TinyGo") }
func tpmExportDAK() error           { panic("TPM unsupported by TinyGo") }
func tpmProveDAK() error            { panic("TPM unsupported by TinyGo") }
func tpmClearCredentials() error    { panic("TPM unsupported by TinyGo") }
