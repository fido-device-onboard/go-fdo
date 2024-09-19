// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"context"
	"crypto/sha512"
	"fmt"
	"io"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// Implement owner service info module for
// https://github.com/fido-alliance/fdo-sim/blob/main/fsim-repository/fdo.download.md

// DownloadContents implements an owner module for fdo.download using a seekable
// reader, such as an [*os.File].
type DownloadContents[T io.ReadSeeker] struct {
	Name         string
	Contents     T
	MustDownload bool
	// Defaults to 1014, by spec
	ChunkSize int

	// internal state
	started bool
	chunk   []byte
	index   int64
	done    bool
}

var _ serviceinfo.OwnerModule = (*DownloadContents[io.ReadSeekCloser])(nil)

// HandleInfo implements serviceinfo.OwnerModule.
func (d *DownloadContents[T]) HandleInfo(ctx context.Context, messageName string, messageBody io.Reader) error {
	switch messageName {
	case "active":
		var deviceActive bool
		if err := cbor.NewDecoder(messageBody).Decode(&deviceActive); err != nil {
			return fmt.Errorf("error decoding message %s: %w", messageName, err)
		}
		if !deviceActive {
			return fmt.Errorf("device service info module is not active")
		}
		return nil

	case "done":
		defer func() {
			if closer, ok := any(d.Contents).(io.Closer); ok {
				_ = closer.Close()
			}
		}()
		var errCode int64
		if err := cbor.NewDecoder(messageBody).Decode(&errCode); err != nil {
			return fmt.Errorf("error decoding message %s: %w", messageName, err)
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
//nolint:gocyclo // Message dispatch has a high score, but is easy to understand
func (d *DownloadContents[T]) ProduceInfo(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	if d.done {
		return false, true, nil
	}

	if d.started {
		return d.sendData(producer)
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
		if len(messageBody) > producer.Available(messageName) {
			return false, false, fmt.Errorf("not enough buffer space to send non-data service info")
		}

		// Write the message
		if err := producer.WriteChunk(messageName, messageBody); err != nil {
			return false, false, err
		}
	}

	// Prepare for data to be sent on the next ProduceInfo
	maxChunkSize := 1014
	if d.ChunkSize > 0 {
		maxChunkSize = d.ChunkSize
	} else if d.ChunkSize < 0 {
		maxChunkSize = (1 << 16) - 1
	}
	d.chunk = make([]byte, maxChunkSize)
	d.started = true
	return false, false, nil
}

func (d *DownloadContents[T]) sendData(producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	const messageName = "data"

	// Seek to and read chunk
	if _, err := d.Contents.Seek(d.index, io.SeekStart); err != nil {
		return false, false, fmt.Errorf("error seeking to next chunk of %q contents: %w", d.Name, err)
	}
	available := producer.Available(messageName) - 6 // 3 for each byte array (double-encoded)
	if available < 1 {
		return false, false, fmt.Errorf("not enough buffer space to send data chunk service info")
	}
	n, err := d.Contents.Read(d.chunk[:min(available, len(d.chunk))])
	if err != nil && err != io.EOF {
		return false, false, fmt.Errorf("error reading chunk of %q contents: %w", d.Name, err)
	} else if n == 0 {
		return false, false, nil
	}
	d.index += int64(n)

	// Marshal chunk
	messageBody, err := cbor.Marshal(d.chunk[:n])
	if err != nil {
		return false, false, err
	}

	// Check that there's enough space to send the message
	if len(messageBody) > producer.Available(messageName) {
		return false, false, nil
	}

	// Write the message
	return false, false, producer.WriteChunk(messageName, messageBody)
}
