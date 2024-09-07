// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"bytes"
	"context"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
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

	// NameToPath optionally overrides the behavior of where Download places
	// the file after downloading to a temporary location.
	NameToPath func(name string) string

	// ErrorLog is optional and any causes of a -1 response will have a
	// corresponding message written.
	ErrorLog io.Writer

	// TODO: Configurable timeout?

	// Message data
	name   string
	length int
	sha384 []byte // optional

	// Internal state
	temp    *os.File
	hash    hash.Hash
	written int
}

var _ serviceinfo.DeviceModule = (*Download)(nil)

// Transition implements serviceinfo.DeviceModule.
func (d *Download) Transition(active bool) error {
	d.reset()
	return nil
}

// Receive implements serviceinfo.DeviceModule.
func (d *Download) Receive(ctx context.Context, messageName string, messageBody io.Reader, respond func(string) io.Writer, yield func()) error {
	if err := d.receive(messageName, messageBody, respond); err != nil {
		d.reset()
		return err
	}
	return nil
}

func (d *Download) receive(messageName string, messageBody io.Reader, respond func(string) io.Writer) error {
	switch messageName {
	case "length":
		return cbor.NewDecoder(messageBody).Decode(&d.length)

	case "sha-384":
		return cbor.NewDecoder(messageBody).Decode(&d.sha384)

	case "name":
		return cbor.NewDecoder(messageBody).Decode(&d.name)

	case "data":
		if err := d.createTemp(); err != nil {
			return err
		}

		for {
			var chunk []byte
			if err := cbor.NewDecoder(messageBody).Decode(&chunk); errors.Is(err, io.EOF) {
				if d.written >= d.length {
					return d.finalize(respond)
				}
				return nil
			} else if err != nil {
				d.reset()
				if d.ErrorLog != nil {
					_, _ = fmt.Fprintf(d.ErrorLog, "[file=%s] error decoding data chunk: %v\n", d.name, err)
				}
				return cbor.NewEncoder(respond("done")).Encode(-1)
			}
			n, err := io.MultiWriter(d.temp, d.hash).Write(chunk)
			if err != nil {
				d.reset()
				if d.ErrorLog != nil {
					_, _ = fmt.Fprintf(d.ErrorLog, "[file=%s] error writing data chunk: %v\n", d.name, err)
				}
				return cbor.NewEncoder(respond("done")).Encode(-1)
			}
			d.written += n
			if debugEnabled() {
				slog.Default().WithGroup("fdo.download").Debug("progress", "written", d.written, "length", d.length)
			}
		}

	default:
		return fmt.Errorf("unknown message %s", messageName)
	}
}

func (d *Download) createTemp() error {
	if d.temp != nil {
		return nil
	}

	var err error
	if d.CreateTemp != nil {
		d.temp, err = d.CreateTemp()
	} else {
		d.temp, err = os.CreateTemp("", "fdo.download_*")
	}
	if err != nil {
		return fmt.Errorf("error creating temp file for download: %w", err)
	}
	return nil
}

func (d *Download) finalize(respond func(string) io.Writer) error {
	defer d.reset()

	// Validate file length and checksum
	if d.written > d.length {
		if d.ErrorLog != nil {
			_, _ = fmt.Fprintf(d.ErrorLog, "[file=%s] %d bytes written, expected a length of %d\n", d.name, d.written, d.length)
		}
		return cbor.NewEncoder(respond("done")).Encode(-1)
	}
	if hashed := d.hash.Sum(nil); len(d.sha384) > 0 && !bytes.Equal(hashed, d.sha384) {
		if d.ErrorLog != nil {
			_, _ = fmt.Fprintf(d.ErrorLog, "[file=%s] checksum failed verification\nexp: %x\ngot: %x\n", d.name, d.sha384, hashed)
		}
		return cbor.NewEncoder(respond("done")).Encode(-1)
	}

	// Rename temp file to final file name
	resolveName := d.NameToPath
	if resolveName == nil {
		resolveName = func(name string) string { return name }
	}
	if d.name == "" {
		if d.ErrorLog != nil {
			_, _ = fmt.Fprintf(d.ErrorLog, "[file=%s] name not sent before data transfer completed\n", d.name)
		}
		return fmt.Errorf("name not sent before data transfer completed")
	}
	if err := os.Rename(d.temp.Name(), resolveName(d.name)); err != nil {
		if d.ErrorLog != nil {
			_, _ = fmt.Fprintf(d.ErrorLog, "[file=%s] error renaming file: %v\n", d.name, err)
		}
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

// Yield implements serviceinfo.DeviceModule.
func (d *Download) Yield(ctx context.Context, respond func(message string) io.Writer, yield func()) error {
	return nil
}
