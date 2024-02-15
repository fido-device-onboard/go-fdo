// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"bytes"
	"context"
	"crypto/sha512"
	"fmt"
	"hash"
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

	// Message data
	name   string
	length int
	sha384 []byte // optional

	// Internal state
	temp    *os.File
	hash    hash.Hash
	written int
}

var _ serviceinfo.Module = (*Download)(nil)

// Transition implements serviceinfo.Module.
func (d *Download) Transition(active bool) { d.reset() }

// Receive implements serviceinfo.Module.
func (d *Download) Receive(ctx context.Context, moduleName, messageName string, messageBody io.Reader, respond func(string) io.Writer) error {
	if err := d.receive(ctx, moduleName, messageName, messageBody, respond); err != nil {
		d.reset()
		return err
	}
	return nil
}

func (d *Download) receive(ctx context.Context, moduleName, messageName string, messageBody io.Reader, respond func(string) io.Writer) error {
	switch messageName {
	case "length":
		return cbor.NewDecoder(messageBody).Decode(&d.length)

	case "sha-384":
		return cbor.NewDecoder(messageBody).Decode(&d.sha384)

	case "name":
		if err := cbor.NewDecoder(messageBody).Decode(&d.name); err != nil {
			return err
		}
		createTemp := d.CreateTemp
		if createTemp == nil {
			createTemp = func() (*os.File, error) {
				return os.CreateTemp("", moduleName+"_*")
			}
		}
		file, err := createTemp()
		if err != nil {
			return err
		}
		d.temp = file
		return nil

	case "data":
		if d.name == "" {
			return fmt.Errorf("module %q did not receive a name before data", moduleName)
		}
		var chunk []byte
		if err := cbor.NewDecoder(messageBody).Decode(&chunk); err != nil {
			d.reset()
			return cbor.NewEncoder(respond("done")).Encode(-1)
		}
		n, err := io.MultiWriter(d.temp, d.hash).Write(chunk)
		if err != nil {
			d.reset()
			return cbor.NewEncoder(respond("done")).Encode(-1)
		}
		d.written += n
		if d.written < d.length {
			return nil
		}
		return d.finalize(respond)

	default:
		return fmt.Errorf("unknown message %s:%s", moduleName, messageName)
	}
}

func (d *Download) finalize(respond func(string) io.Writer) error {
	defer d.reset()

	// Validate file length and checksum
	if d.written > d.length {
		return cbor.NewEncoder(respond("done")).Encode(-1)
	}
	if hashed := d.hash.Sum(nil); len(d.sha384) > 0 && !bytes.Equal(hashed, d.sha384) {
		return cbor.NewEncoder(respond("done")).Encode(-1)
	}

	// Rename temp file to final file name
	rename := d.Rename
	if rename == nil {
		rename = func(name string) error { return os.Rename(d.temp.Name(), name) }
	}
	if err := rename(d.name); err != nil {
		return cbor.NewEncoder(respond("done")).Encode(-1)
	}

	// Send done message
	return cbor.NewEncoder(respond("done")).Encode(d.written)
}

func (d *Download) reset() {
	if d.temp != nil {
		_ = d.temp.Close()
		_ = os.Remove(d.temp.Name())
	}
	if d.hash == nil {
		d.hash = sha512.New384()
	}
	d.hash.Reset()
	d.name, d.length, d.sha384, d.temp, d.written = "", 0, nil, nil, 0
}
