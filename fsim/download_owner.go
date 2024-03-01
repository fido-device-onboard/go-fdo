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
	started bool
	index   int64
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
		// TODO: Check that active is true
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

	if d.started {
		return d.sendData(moduleName, producer)
	}

	// Hash contents and seek back to start
	sha384 := sha512.New384()
	length, err := io.Copy(sha384, d.Contents)
	if err != nil {
		return false, false, fmt.Errorf("error reading contents of %q: %w", d.Name, err)
	}

	messageVal := map[string]any{
		"active":  true,
		"name":    d.Name,
		"length":  length,
		"sha-384": sha384.Sum(nil)[:],
	}
	for _, messageName := range []string{"active", "name", "length", "sha-384"} {
		messageBody, err := cbor.Marshal(messageVal[messageName])
		if err != nil {
			return false, false, err
		}

		// Check that there's enough space to send the message
		if len(messageBody) > producer.Available(moduleName, messageName) {
			return false, false, fmt.Errorf("not enough buffer space to send non-data service info")
		}

		// Write the message
		if err := producer.WriteChunk(moduleName, messageName, messageBody); err != nil {
			return false, false, err
		}
	}

	d.started = true
	return false, false, nil
}

func (d *DownloadContents[T]) sendData(moduleName string, producer *serviceinfo.Producer) (blockPeer, fsimDone bool, _ error) {
	const messageName = "data"

	// Seek to and read chunk
	if _, err := d.Contents.Seek(d.index, io.SeekStart); err != nil {
		return false, false, fmt.Errorf("error seeking to next chunk of %q contents: %w", d.Name, err)
	}
	available := producer.Available(moduleName, messageName) - 3 // 3 for the possible length of the byte array
	if available < 1 {
		return false, false, fmt.Errorf("not enough buffer space to send data chunk service info")
	}
	chunk := make([]byte, min(available, 1014))
	n, err := d.Contents.Read(chunk)
	if err != nil && err != io.EOF {
		return false, false, fmt.Errorf("error reading chunk of %q contents: %w", d.Name, err)
	} else if n == 0 {
		return false, false, nil
	}
	d.index += int64(n)
	chunk = chunk[:n]

	// Marshal chunk
	messageBody, err := cbor.Marshal(chunk)
	if err != nil {
		return false, false, err
	}

	// Check that there's enough space to send the message
	if len(messageBody) > producer.Available(moduleName, messageName) {
		return false, false, nil
	}

	// Write the message
	return false, false, producer.WriteChunk(moduleName, messageName, messageBody)
}
