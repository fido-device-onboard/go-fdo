// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package testdata contains test fixtures.
package testdata

import "embed"

//go:embed dc.bin
//go:embed mfg_key.pem
//go:embed ov.pem
var Files embed.FS
