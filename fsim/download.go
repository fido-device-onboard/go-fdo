// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"bytes"
	"context"
	"crypto/sha512"
	"fmt"
	"io"
	"os"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// Download implements https://github.com/fido-alliance/fdo-sim/blob/main/fsim-repository/fdo.download.md
// and should be registered to the "fdo.download" module.
type Download struct {
	// CreateTemp optionally overrides the behavior of how the FSIM creates a
	// temporary file to download to.
	CreateTemp func() (*os.File, error)

	// Rename optionally overrides the behavior of where Download places the
	// file after downloading to a temporary location.
	Rename func(name string) error

	// Internal state
	name   string
	length uint
	sha384 []byte // optional
}

var _ serviceinfo.Module = (*Download)(nil)

// Receive implements serviceinfo.Module.
func (d *Download) Receive(ctx context.Context, moduleName, messageName string, messageBody io.Reader) error {
	switch messageName {
	case "active":
		return nil
	case "name":
		return cbor.NewDecoder(messageBody).Decode(&d.name)
	case "length":
		return cbor.NewDecoder(messageBody).Decode(&d.length)
	case "sha-384":
		return cbor.NewDecoder(messageBody).Decode(&d.sha384)
	case "data":
		// continue
	default:
		return fmt.Errorf("unknown message %s:%s", moduleName, messageName)
	}

	// Create a temp file
	createTemp := d.CreateTemp
	if createTemp == nil {
		createTemp = func() (*os.File, error) {
			return os.CreateTemp("", moduleName+"_*")
		}
	}
	file, err := createTemp()
	if err != nil {
		return fmt.Errorf("error creating temp file for download: %w", err)
	}
	defer func() { _ = file.Close() }()

	// Download into a temp file
	hash := sha512.New384()
	n, err := io.Copy(io.MultiWriter(file, hash), messageBody)
	if err != nil {
		return fmt.Errorf("error creating temp file for download: %w", err)
	}
	if n != int64(d.length) {
		return fmt.Errorf("expected file %q to be length %d, got %d", d.name, d.length, n)
	}
	if hashed := hash.Sum(nil); len(d.sha384) > 0 && !bytes.Equal(hashed, d.sha384) {
		return fmt.Errorf("file %q SHA384 hash did not match", d.name)
	}

	// Rename temp file to final file name
	rename := d.Rename
	if rename == nil {
		rename = func(name string) error { return os.Rename(file.Name(), name) }
	}
	if d.name == "" {
		return fmt.Errorf("module %q did not receive a name before data", moduleName)
	}
	return rename(d.name)
}

// Respond implements serviceinfo.Module.
func (d *Download) Respond(ctx context.Context, sendInfo func(message string) io.Writer) error {
	// Send active and done messages
	if err := cbor.NewEncoder(sendInfo("active")).Encode(true); err != nil {
		return err
	}
	if err := cbor.NewEncoder(sendInfo("done")).Encode(d.length); err != nil {
		return err
	}

	// Reset internal state
	d.name, d.length, d.sha384 = "", 0, nil

	return nil
}
