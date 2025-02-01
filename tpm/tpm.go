// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package tpm implements device credentials using the TPM Draft Spec. See
// https://fidoalliance.org/specs/FDO/securing-fdo-in-tpm-v1.0-rd-20231010/securing-fdo-in-tpm-v1.0-rd-20231010.html.
//
// To create a [TPM] or [Closer] instance satisfying the interface you can use
// a transport from github.com/google/go-tpm/transport.
//
// On Linux, you may use the Open function from
// github.com/google/go-tpm/tpm2/transport/linuxtpm.
//
// It is highly recommended to use a TPM Resource Manager to mitigate TPM
// resource exhaustion, such as the one implemented in the Linux kernel:
//
//	linuxtpm.Open("/dev/tpmrm0")
//
// It is discouraged to directly use a TPM (e.g. "/dev/tpm0").
package tpm

import "github.com/google/go-tpm/tpm2/transport"

// TPM represents a logical connection to a TPM.
//
// This type aliases the interface from github.com/google/go-tpm/transport.
type TPM = transport.TPM

// Closer represents a logical connection to a TPM and you can close it.
//
// This type aliases the interface from github.com/google/go-tpm/transport.
type Closer = transport.TPMCloser
