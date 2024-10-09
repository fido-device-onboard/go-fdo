// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

//go:build !tinygo

package sqlite

import (
	"database/sql"
	"fmt"
	"path/filepath"

	"github.com/ncruces/go-sqlite3/driver"  // Load database/sql driver
	_ "github.com/ncruces/go-sqlite3/embed" // Load sqlite WASM binary

	_ "github.com/fido-device-onboard/go-fdo/sqlite/xts" // Encryption VFS
)

// New creates or opens a SQLite database file using a single non-pooled
// connection. If a password is specified, then the xts VFS will be used
// with a text key.
func New(filename, password string) (*DB, error) {
	var query string
	if password != "" {
		query += fmt.Sprintf("&vfs=xts&_pragma=textkey(%q)", password)
	}
	connector, err := (&driver.SQLite{}).OpenConnector("file:" + filepath.Clean(filename) + query)
	if err != nil {
		return nil, fmt.Errorf("error creating sqlite connector: %w", err)
	}
	db := sql.OpenDB(connector)
	return Init(db)
}
