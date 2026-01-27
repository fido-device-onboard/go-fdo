// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"bytes"
	"context"
	"crypto/sha512"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

const defaultWgetTimeout = time.Hour

// Wget implements https://github.com/fido-alliance/fdo-sim/blob/main/fsim-repository/fdo.wget.md
// and should be registered to the "fdo.wget" module.
type Wget struct {
	// CreateTemp optionally overrides the behavior of how the FSIM creates a
	// temporary file to download to.
	CreateTemp func() (*os.File, error)

	// NameToPath optionally overrides the behavior of where Wget places
	// the file after downloading to a temporary location.
	NameToPath func(name string) string

	// Timeout determines the maximum amount of time to allow downloading data.
	// Exceeding this time will result in the module sending an error. If
	// Timeout is zero, then a default of 1 hour will be used.
	Timeout time.Duration

	// Client is the HTTP client to use. If nil, http.DefaultClient will be
	// used.
	Client *http.Client

	// Message data
	name   string
	sha384 []byte // optional

	// Internal state
	resultCh <-chan wgetResult
	cancel   context.CancelFunc
}

type wgetResult struct {
	len int64
	err error
}

var _ serviceinfo.DeviceModule = (*Wget)(nil)

// Transition implements serviceinfo.DeviceModule.
func (d *Wget) Transition(active bool) error {
	d.reset()
	return nil
}

// Receive implements serviceinfo.DeviceModule.
func (d *Wget) Receive(ctx context.Context, messageName string, messageBody io.Reader, respond func(string) io.Writer, yield func()) error {
	if err := d.receive(ctx, messageName, messageBody); err != nil {
		d.reset()
		return err
	}
	return nil
}

func (d *Wget) receive(ctx context.Context, messageName string, messageBody io.Reader) error {
	switch messageName {
	case "sha-384":
		return cbor.NewDecoder(messageBody).Decode(&d.sha384)

	case "name":
		return cbor.NewDecoder(messageBody).Decode(&d.name)

	case "url":
		var url string
		if err := cbor.NewDecoder(messageBody).Decode(&url); err != nil {
			return err
		}

		resultCh := make(chan wgetResult)
		d.resultCh = resultCh

		timeout := d.Timeout
		if timeout <= 0 {
			timeout = defaultWgetTimeout
		}
		ctx, d.cancel = context.WithTimeout(ctx, timeout)

		go func() {
			n, err := d.download(ctx, url)
			resultCh <- wgetResult{len: n, err: err}
		}()

		return nil

	default:
		return fmt.Errorf("unknown message %s", messageName)
	}
}

func (d *Wget) download(ctx context.Context, url string) (_ int64, err error) {
	// Create a temp file
	var temp *os.File
	if d.CreateTemp != nil {
		temp, err = d.CreateTemp()
	} else {
		temp, err = os.CreateTemp("", "fdo.wget_*")
	}
	if err != nil {
		return 0, fmt.Errorf("error creating temp file for download: %w", err)
	}
	defer func() { _ = os.Remove(temp.Name()) }()
	defer func() { _ = temp.Close() }()

	// Make HTTP GET request
	client := d.Client
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("error creating request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("error making request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	// TODO: Spawn goroutine to log progress at regular intervals
	//
	// if debugEnabled() {
	// 	slog.Default().WithGroup("fdo.wget").Debug("progress", "written", written, "length", resp.ContentLength)
	// }

	// Write to temp file and hash
	hash := sha512.New384()
	w := io.MultiWriter(temp, hash)
	n, err := io.Copy(w, resp.Body)
	if err != nil {
		return 0, fmt.Errorf("error saving response: %w", err)
	}

	// Validate file checksum
	if hashed := hash.Sum(nil); len(d.sha384) > 0 && !bytes.Equal(hashed, d.sha384) {
		return 0, fmt.Errorf("checksum of %q failed verification: expected: %x, got: %x", d.name, d.sha384, hashed)
	}

	// Move temp file to final file name
	resolveName := d.NameToPath
	if resolveName == nil {
		resolveName = func(name string) string { return name }
	}
	if d.name == "" {
		return 0, fmt.Errorf("name not sent before file download completed")
	}
	if err := moveFile(temp.Name(), resolveName(d.name)); err != nil {
		return 0, fmt.Errorf("error moving file to %q: %w", d.name, err)
	}

	return n, nil
}

// Yield implements serviceinfo.DeviceModule.
func (d *Wget) Yield(ctx context.Context, respond func(message string) io.Writer, yield func()) error {
	select {
	case result := <-d.resultCh:
		defer d.reset()

		if result.err != nil {
			return cbor.NewEncoder(respond("error")).Encode(result.err.Error())
		}

		return cbor.NewEncoder(respond("done")).Encode(result.len)

	default:
		return nil
	}
}

func (d *Wget) reset() {
	if d.cancel != nil {
		d.cancel()
	}
	d.name = ""
	d.sha384 = nil
	d.resultCh = nil
}
