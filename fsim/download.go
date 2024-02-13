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
	"time"

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
	length int
	sha384 []byte // optional

	temp    *os.File
	hash    hash.Hash
	written int
	chunk   []byte
}

var _ serviceinfo.Module = (*Download)(nil)

// Transition implements serviceinfo.Module.
func (d *Download) Transition(active bool) {
	if active {
		// No setup code
		return
	}

	// Tear-down code
	d.reset()
}

// Receive implements serviceinfo.Module.
func (d *Download) Receive(ctx context.Context, moduleName, messageName string, messageBody io.Reader, respond func(string) io.Writer) error {
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
		d.temp, d.hash = file, sha512.New384()
		return nil

	case "data":
		if d.name == "" {
			return fmt.Errorf("module %q did not receive a name before data", moduleName)
		}
		if err := cbor.NewDecoder(messageBody).Decode(&d.chunk); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] %v\n", time.Now(), err)
			d.reset()
			return cbor.NewEncoder(respond("done")).Encode(-1)
		}
		n, err := io.MultiWriter(d.temp, d.hash).Write(d.chunk)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[%s] %v\n", time.Now(), err)
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
	// Validate file length and checksum
	if d.written > d.length {
		fmt.Fprintf(os.Stderr, "[%s] %v\n", time.Now(), fmt.Errorf("length does not match: wrote %d, expected %d", d.written, d.length))
		d.reset()
		return cbor.NewEncoder(respond("done")).Encode(-1)
	}
	if hashed := d.hash.Sum(nil); len(d.sha384) > 0 && !bytes.Equal(hashed, d.sha384) {
		fmt.Fprintf(os.Stderr, "[%s] %v\n", time.Now(), fmt.Errorf("checksum does not match\nexpected: %x\n     got: %x", d.sha384, hashed))
		d.reset()
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
	_ = d.temp.Close()
	_ = os.Remove(d.temp.Name())
	d.name, d.length, d.sha384, d.temp, d.hash, d.written, d.chunk = "", 0, nil, nil, nil, 0, nil
}
