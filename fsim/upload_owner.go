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
	"os"
	"path/filepath"
	"sync"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// Implement owner service info module for
// https://github.com/fido-alliance/fdo-sim/blob/main/fsim-repository/fdo.upload.md

const fdoUploadModule = "fdo.upload"

// UploadRequest implements the fdo.upload owner module.
type UploadRequest struct {
	// Directory to place uploaded file
	Dir string

	// Name to use in upload request
	Name string

	// Optional name to use on local filesystem
	Rename string

	// CreateTemp optionally overrides the behavior of how the module creates a
	// temporary file to download to.
	CreateTemp func() (*os.File, error)

	// internal state
	requested bool
	length    int64
	written   int64
	sha384    []byte

	once sync.Once
	temp *os.File
	hash hash.Hash
}

var _ serviceinfo.OwnerModule = (*UploadRequest)(nil)

// HandleInfo implements serviceinfo.OwnerModule.
func (u *UploadRequest) HandleInfo(ctx context.Context, messageName string, messageBody io.Reader) error {
	switch messageName {
	case "active":
		// TODO: Check that active is true
		var ignore bool
		if err := cbor.NewDecoder(messageBody).Decode(&ignore); err != nil {
			return fmt.Errorf("error decoding message %s:%s: %w", fdoUploadModule, messageName, err)
		}
		return nil

	case "length":
		if err := cbor.NewDecoder(messageBody).Decode(&u.length); err != nil {
			return fmt.Errorf("error decoding message %s:%s: %w", fdoUploadModule, messageName, err)
		}
		return nil

	case "data":
		var err error
		u.once.Do(func() {
			createTemp := u.CreateTemp
			if createTemp == nil {
				createTemp = func() (*os.File, error) {
					return os.CreateTemp("", "fdo.upload_*")
				}
			}
			u.temp, err = createTemp()
			u.hash = sha512.New384()
		})
		if err != nil {
			return fmt.Errorf("error creating temp file for upload of %q: %w", u.Name, err)
		}
		var chunk []byte
		for {
			if err := cbor.NewDecoder(messageBody).Decode(&chunk); errors.Is(err, io.EOF) {
				break
			} else if err != nil {
				return fmt.Errorf("error decoding message %s:%s: %w", fdoUploadModule, messageName, err)
			}
			n, err := io.MultiWriter(u.temp, u.hash).Write(chunk)
			if err != nil {
				return fmt.Errorf("error writing upload data chunk of %q: %w", u.Name, err)
			}
			u.written += int64(n)
		}
		return nil

	case "sha-384":
		if err := cbor.NewDecoder(messageBody).Decode(&u.sha384); err != nil {
			return fmt.Errorf("error decoding message %s:%s: %w", fdoUploadModule, messageName, err)
		}
		return nil

	default:
		return fmt.Errorf("unsupported message %q", messageName)
	}
}

// ProduceInfo implements serviceinfo.OwnerModule.
func (u *UploadRequest) ProduceInfo(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	if !u.requested {
		return u.request(producer)
	}
	if len(u.sha384) > 0 && u.length > 0 && u.written >= u.length {
		return u.finalize()
	}
	return false, false, nil
}

func (u *UploadRequest) request(producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	// Marshal message bodies
	trueBody, err := cbor.Marshal(true)
	if err != nil {
		return false, false, err
	}
	nameBody, err := cbor.Marshal(u.Name)
	if err != nil {
		return false, false, err
	}

	// Send upload messages
	if err := producer.WriteChunk("active", trueBody); err != nil {
		return false, false, err
	}
	if err := producer.WriteChunk("need-sha", trueBody); err != nil {
		return false, false, err
	}
	if err := producer.WriteChunk("name", nameBody); err != nil {
		return false, false, err
	}

	u.requested = true
	return false, false, nil
}

func (u *UploadRequest) finalize() (blockPeer, moduleDone bool, _ error) {
	if u.written > u.length {
		return false, false, fmt.Errorf("uploaded file %q: received %d bytes, expected %d", u.Name, u.written, u.length)
	}
	if !bytes.Equal(u.sha384, u.hash.Sum(nil)[:]) {
		return false, false, fmt.Errorf("uploaded file %q: SHA-384 did not match", u.Name)
	}
	if err := u.temp.Close(); err != nil {
		return false, false, fmt.Errorf("error closing temp file for upload %q: %w", u.Name, err)
	}
	// TODO: Enforce chroot-like security
	if u.Rename == "" {
		u.Rename = filepath.Base(u.Name)
	}
	oldpath, newpath := u.temp.Name(), filepath.Join(u.Dir, u.Rename)
	if err := os.Rename(oldpath, newpath); err != nil {
		return false, false, fmt.Errorf("error renaming temp file %q to %q: %w", oldpath, newpath, err)
	}
	return false, true, nil
}
