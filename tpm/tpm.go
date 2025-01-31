// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package tpm implements device credentials using the
// [TPM Draft Spec](https://fidoalliance.org/specs/FDO/securing-fdo-in-tpm-v1.0-rd-20231010/securing-fdo-in-tpm-v1.0-rd-20231010.html).
package tpm

import "github.com/google/go-tpm/tpm2/transport"

// TPM represents a logical connection to a TPM.
//
// This type aliases the interface from github.com/google/go-tpm/transport.
//
// To create an instance satisfying this interface on Linux, the Open function
// from github.com/google/go-tpm/tpm2/transport/linuxtpm may be used.
type TPM = transport.TPM

// Closer represents a logical connection to a TPM and you can close it.
//
// This type aliases the interface from github.com/google/go-tpm/transport.
//
// To create an instance satisfying this interface on Linux, the Open function
// from github.com/google/go-tpm/tpm2/transport/linuxtpm may be used.
type Closer = transport.TPMCloser
