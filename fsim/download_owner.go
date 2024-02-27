// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"context"
	"crypto/sha512"
	"fmt"
	"io"
	"os"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// Implement owner service info module for
// https://github.com/fido-alliance/fdo-sim/blob/main/fsim-repository/fdo.download.md

const fdoDownloadModule = "fdo.download"

// DownloadContents implements an owner FSIM for fdo.download using a seekable
// reader, such as an [*os.File].
type DownloadContents[T io.ReadSeeker] struct {
	Name         string
	Contents     T
	MustDownload bool

	// internal state
	prevMsg string
	index   int64
	sha384  [48]byte
	done    bool
}

var _ serviceinfo.OwnerModule = (*DownloadContents[*os.File])(nil)

// HandleInfo implements serviceinfo.OwnerModule.
func (d *DownloadContents[T]) HandleInfo(ctx context.Context, moduleName, messageName string, messageBody io.Reader) error {
	if moduleName != fdoDownloadModule {
		return fmt.Errorf("invalid module name %q, expected %q", moduleName, fdoDownloadModule)
	}
	switch messageName {
	case "active":
		var ignore bool
		if err := cbor.NewDecoder(messageBody).Decode(&ignore); err != nil {
			return fmt.Errorf("error decoding message %s:%s: %w", moduleName, messageName, err)
		}
		return nil

	case "done":
		var errCode int64
		if err := cbor.NewDecoder(messageBody).Decode(&errCode); err != nil {
			return fmt.Errorf("error decoding message %s:%s: %w", moduleName, messageName, err)
		}
		if errCode == -1 && d.MustDownload {
			return fmt.Errorf("device failed to download %q", d.Name)
		}
		if errCode != -1 && errCode != d.index {
			return fmt.Errorf("device downloaded %d bytes, expected %d", errCode, d.index)
		}
		d.done = true
		return nil

	default:
		return fmt.Errorf("unsupported message %q", messageName)
	}
}

// ProduceInfo implements serviceinfo.OwnerModule.
//
//nolint:gocyclo, Message dispatch has a high score, but is easy to understand
func (d *DownloadContents[T]) ProduceInfo(ctx context.Context, lastDeviceInfoEmpty bool, producer *serviceinfo.Producer) (blockPeer, fsimDone bool, _ error) {
	if d.done {
		return false, true, nil
	}

	const moduleName = fdoDownloadModule

	var messageName string
	var messageBody []byte
	switch d.prevMsg {
	case "":
		messageName = "active"

		var err error
		messageBody, err = cbor.Marshal(true)
		if err != nil {
			return false, false, err
		}

	case "active":
		messageName = "name"

		var err error
		messageBody, err = cbor.Marshal(d.Name)
		if err != nil {
			return false, false, err
		}

	case "name":
		messageName = "length"

		// Hash contents and seek back to start
		sha384 := sha512.New384()
		n, err := io.Copy(sha384, d.Contents)
		if err != nil {
			return false, false, fmt.Errorf("error reading contents of %q: %w", d.Name, err)
		}
		sha384.Sum(d.sha384[:0])
		if _, err := d.Contents.Seek(0, io.SeekStart); err != nil {
			return false, false, fmt.Errorf("error seeking back to start of %q contents: %w", d.Name, err)
		}

		messageBody, err = cbor.Marshal(n)
		if err != nil {
			return false, false, err
		}

	case "length":
		messageName = "sha-384"

		var err error
		messageBody, err = cbor.Marshal(d.sha384)
		if err != nil {
			return false, false, err
		}

	case "sha-384", "data":
		messageName = "data"

		// Seek to and read chunk
		if _, err := d.Contents.Seek(d.index, io.SeekStart); err != nil {
			return false, false, fmt.Errorf("error seeking to next chunk of %q contents: %w", d.Name, err)
		}
		available := producer.Available(moduleName, messageName) - 3 // 3 for the possible length of the byte array
		if available < 1 {
			break
		}
		chunk := make([]byte, min(available, 1014))
		if n, err := d.Contents.Read(chunk); err != nil && err != io.EOF {
			return false, false, fmt.Errorf("error reading chunk of %q contents: %w", d.Name, err)
		} else if n == 0 {
			return false, false, nil
		} else {
			d.index += int64(n)
			chunk = chunk[:n]
		}

		var err error
		messageBody, err = cbor.Marshal(chunk)
		if err != nil {
			return false, false, err
		}

	default:
		panic("Programming error - set invalid previous message name")
	}

	// Check that there's enough space to send the message
	if len(messageBody) > producer.Available(moduleName, messageName) {
		return false, false, nil
	}

	// Write the message
	d.prevMsg = messageName
	return false, false, producer.WriteChunk(moduleName, messageName, messageBody)
}
