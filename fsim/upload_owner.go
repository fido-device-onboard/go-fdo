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
	"syscall"

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

// sameFilesystem checks if two paths are on the same filesystem by comparing device IDs
func sameFilesystem(path1, path2 string) (bool, error) {
	var stat1, stat2 syscall.Stat_t

	if err := syscall.Stat(path1, &stat1); err != nil {
		return false, err
	}
	if err := syscall.Stat(path2, &stat2); err != nil {
		return false, err
	}

	return stat1.Dev == stat2.Dev, nil
}

// backupExistingFile renames an existing file with a timestamp suffix if it exists
func backupExistingFile(root *os.Root, filename string) error {
	info, err := root.Stat(filename)
	if err != nil {
		// File doesn't exist, nothing to backup
		return nil
	}

	// File exists, rename it with timestamp from its modification time
	timestamp := info.ModTime().Format("20060102150405.000000")
	ext := filepath.Ext(filename)
	nameWithoutExt := filename[:len(filename)-len(ext)]
	backupName := fmt.Sprintf("%s.%s%s", nameWithoutExt, timestamp, ext)

	if err := root.Rename(filename, backupName); err != nil {
		return fmt.Errorf("error renaming existing file %q to %q: %w", filename, backupName, err)
	}

	return nil
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
	if u.Rename == "" {
		u.Rename = filepath.Base(u.Name)
	}

	// Create a rooted filesystem to prevent path traversal attacks
	rootDir, err := os.OpenRoot(u.Dir)
	if err != nil {
		return false, false, fmt.Errorf("error creating root filesystem for %q: %w", u.Dir, err)
	}
	defer rootDir.Close()

	tempFilePath := u.temp.Name()
	// Remove the temp file when exiting, ignore errors
	defer os.Remove(tempFilePath)

	// Check if temp file and destination directory are on the same filesystem
	samefs, err := sameFilesystem(tempFilePath, u.Dir)
	if err != nil {
		return false, false, fmt.Errorf("error checking filesystem for temp file and destination: %w", err)
	}

	if samefs {
		// Same filesystem - we can use rename for efficiency
		// Construct the actual destination path
		destPath := filepath.Join(u.Dir, u.Rename)

		// Verify the resolved path is still within u.Dir (security check)
		realDest, err := filepath.EvalSymlinks(u.Dir)
		if err != nil {
			realDest = u.Dir
		}
		realDestFile := filepath.Join(realDest, u.Rename)
		if !filepath.IsLocal(u.Rename) || filepath.Dir(realDestFile) != realDest {
			return false, false, fmt.Errorf("path traversal detected in rename: %q", u.Rename)
		}

		// Backup existing file if present
		if err = backupExistingFile(rootDir, u.Rename); err != nil {
			return false, false, err
		}

		// Perform the rename
		if err = os.Rename(tempFilePath, destPath); err != nil {
			return false, false, fmt.Errorf("error renaming temp file to %q: %w", u.Rename, err)
		}
	} else {
		// Different filesystems - fall back to copy
		// Open the temp file for reading
		src, err := os.Open(tempFilePath)
		if err != nil {
			return false, false, fmt.Errorf("error opening temp file %q: %w", tempFilePath, err)
		}
		defer src.Close()

		// Backup existing file if present
		if err = backupExistingFile(rootDir, u.Rename); err != nil {
			return false, false, err
		}

		// Create the destination file within the rooted filesystem
		// This ensures u.Rename cannot escape u.Dir even with path traversal
		dst, err := rootDir.Create(u.Rename)
		if err != nil {
			return false, false, fmt.Errorf("error creating destination file %q: %w", u.Rename, err)
		}
		defer dst.Close()

		// Copy the data
		if _, err = io.Copy(dst, src); err != nil {
			return false, false, fmt.Errorf("error copying to destination file %q: %w", u.Rename, err)
		}
	}
	return false, true, nil
}
