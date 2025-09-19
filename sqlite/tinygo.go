// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

//go:build tinygo

package sqlite

// Open is not implemented for tinygo, because it requires embedding a WASM
// runtime in the binary.
func Open(filename, password string) (*DB, error) {
	panic("sqlite not supported by TinyGo")
}
