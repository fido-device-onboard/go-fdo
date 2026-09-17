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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// Implement owner service info module for
// https://github.com/fido-alliance/fdo-sim/blob/main/fsim-repository/fdo.upload.md

// UploadRequest implements the fdo.upload owner module.
type UploadRequest struct {
	// Directory to place uploaded file
	Dir string

	// Name to use in upload request
	Name string

	// Rename func optionally overrides the behavior of how the module saves
	// the device file to the local filesystem
	Rename func(string) string

	// CreateTemp optionally overrides the behavior of how the module creates a
	// temporary file to download to.
	CreateTemp func() (*os.File, error)

	// Ovewrite makes the module to ovewrite the local file if it already exist
	Overwrite bool

	// MakeDirectories creates the parent directories for the uploaded file
	// if they don't already exist
	MakeDirectories bool

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
		var deviceActive bool
		if err := cbor.NewDecoder(messageBody).Decode(&deviceActive); err != nil {
			return fmt.Errorf("error decoding message %s: %w", messageName, err)
		}
		if !deviceActive {
			return fmt.Errorf("device service info module is not active")
		}
		return nil

	case "length":
		if err := cbor.NewDecoder(messageBody).Decode(&u.length); err != nil {
			return fmt.Errorf("error decoding message %s: %w", messageName, err)
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
				return fmt.Errorf("error decoding message %s: %w", messageName, err)
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
			return fmt.Errorf("error decoding message %s: %w", messageName, err)
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

	// Enforce chroot-like security using os.OpenRoot
	// Create a rooted filesystem to prevent path traversal attacks
	rootDir, err := os.OpenRoot(u.Dir)
	if err != nil {
		return false, false, fmt.Errorf("error creating '%q' as root dir for uploads: %w", u.Dir, err)
	}
	defer func() { _ = rootDir.Close() }()

	rootDirName := rootDir.Name()
	tempFileName := u.temp.Name()

	defer func() { _ = os.Remove(tempFileName) }()

	// Check if temp file and destination directory are on the same filesystem
	samefs, err := sameFilesystem(tempFileName, rootDirName)
	if err != nil {
		return false, false, fmt.Errorf("error checking filesystem for temp file and destination: %w", err)
	}

	if u.Rename == nil {
		u.Rename = func(name string) string {
			return strings.TrimLeft(name, "/")
		}
	}

	// Construct the actual destination filename (relative to u.Dir)
	// Clean the path to prevent traversal attacks with ../
	dstFileName := filepath.Clean(u.Rename(u.Name))

	// Use rootDir to validate the destination path doesn't escape
	var dstFileInfo fs.FileInfo
	dstFileInfo, err = rootDir.Stat(dstFileName)
	// The file exists and overwrite is false
	if err == nil && !u.Overwrite {
		return false, false, fmt.Errorf("'%s' already exists", dstFileInfo.Name())
	}
	// The was an unexpected error
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, false, err
	}

	if u.MakeDirectories {
		// Create parent directories if needed
		if err = rootDir.MkdirAll(filepath.Dir(dstFileName), 0o755); err != nil {
			return false, false, fmt.Errorf("error creating parent directories for %q: %w", dstFileName, err)
		}
	}

	// Construct the full destination path for operations outside rootDir
	dstFilePath := filepath.Join(u.Dir, dstFileName)

	// Same filesystem - we can use rename for efficiency
	// Use os.Rename since temp file is outside the rooted directory
	if samefs {
		if err = os.Rename(tempFileName, dstFilePath); err != nil {
			return false, false, fmt.Errorf("error renaming temp file %q to %q: %w", tempFileName, dstFilePath, err)
		}
		return false, true, nil
	}

	// Different filesystems - fall back to copy
	return false, true, u.copyFile(tempFileName, rootDir, dstFileName)
}

// copyFile copies a file from src path to dst within the rooted filesystem.
func (u *UploadRequest) copyFile(srcPath string, rootDir *os.Root, dstName string) error {
	// Open the temp file for reading
	// #nosec G304 -- srcPath is the temp file path we created in CreateTemp, not user input
	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("error opening temp file %q: %w", srcPath, err)
	}
	defer func() { _ = src.Close() }()

	// Create the destination file within the rooted filesystem
	// This ensures u.Rename cannot escape u.Dir even with path traversal
	dst, err := rootDir.Create(dstName)
	if err != nil {
		return fmt.Errorf("error creating destination file %q: %w", dstName, err)
	}
	defer func() { _ = dst.Close() }()

	// Copy the data
	if _, err = io.Copy(dst, src); err != nil {
		return fmt.Errorf("error copying to destination file %q: %w", dstName, err)
	}
	return nil
}
