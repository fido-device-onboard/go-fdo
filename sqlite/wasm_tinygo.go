// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

//go:build tinygo

package sqlite

import "fmt"

// New is not implemented for tinygo, because it requires embedding a WASM
// runtime in the binary.
func New(filename, password string) (*DB, error) {
	return nil, fmt.Errorf("not supported in tinygo")
}
