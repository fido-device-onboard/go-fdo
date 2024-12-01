// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

//go:build !tinygo

// Open is not implemented for tinygo, because it requires embedding a WASM
// runtime in the binary.

package sqlite

import (
	"database/sql"
	"fmt"
	"path/filepath"

	"github.com/ncruces/go-sqlite3/driver"    // Load database/sql driver
	_ "github.com/ncruces/go-sqlite3/embed"   // Load sqlite WASM binary
	_ "github.com/ncruces/go-sqlite3/vfs/xts" // Encryption VFS
)

// Open creates or opens a SQLite database file using a single non-pooled
// connection. If a password is specified, then the xts VFS will be used
// with a text key.
func Open(filename, password string) (*DB, error) {
	query := "?_pragma=foreign_keys(on)"
	if password != "" {
		query += fmt.Sprintf("&vfs=xts&_pragma=textkey(%q)&_pragma=temp_store(memory)", password)
	}
	connector, err := (&driver.SQLite{}).OpenConnector("file:" + filepath.Clean(filename) + query)
	if err != nil {
		return nil, fmt.Errorf("error creating sqlite connector: %w", err)
	}
	db := sql.OpenDB(connector)
	if err := Init(db); err != nil {
		return nil, err
	}
	return New(db), nil
}
