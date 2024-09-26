// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package xts implements AES-XTS encryption for SQLite as a VFS. If a text key
// is provided, PBKDF2 with SHA512 and 10k iterations is used.
package xts

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/ncruces/go-sqlite3"
	"github.com/ncruces/go-sqlite3/vfs"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/xts"
)

func init() {
	Register("xts", vfs.Find(""))
}

// Register registers an encrypting VFS, wrapping a base VFS, using an AES-XTS cipher. The key is
// derived using PBKDF2 with SHA512 and 10k iterations.
func Register(name string, base vfs.VFS) {
	vfs.Register(name, &xtsVFS{
		VFS: base,
	})
}

var salt = []byte("github.com/fido-device-onboard/go-fdo/sqlite/xts")

func kdf(secret string) []byte {
	if secret == "" {
		key := make([]byte, 32)
		n, _ := rand.Read(key)
		return key[:n]
	}
	return pbkdf2.Key([]byte(secret), salt, 10_000, 32, sha512.New)
}

func newCipher(key []byte) (*xts.Cipher, error) {
	return xts.NewCipher(aes.NewCipher, key)
}

type xtsVFS struct {
	vfs.VFS
}

func (x *xtsVFS) Open(name string, flags vfs.OpenFlag) (vfs.File, vfs.OpenFlag, error) {
	return nil, 0, sqlite3.CANTOPEN
}

func (x *xtsVFS) OpenFilename(name *vfs.Filename, flags vfs.OpenFlag) (file vfs.File, _ vfs.OpenFlag, err error) {
	if hf, ok := x.VFS.(vfs.VFSFilename); ok {
		file, flags, err = hf.OpenFilename(name, flags)
	} else {
		file, flags, err = x.VFS.Open(name.String(), flags)
	}

	// Encrypt everything except super journals and memory files.
	if err != nil || flags&(vfs.OPEN_SUPER_JOURNAL|vfs.OPEN_MEMORY) != 0 {
		return file, flags, err
	}

	if f, ok := name.DatabaseFile().(*xtsFile); ok {
		if f.cipher == nil {
			return nil, flags, sqlite3.CANTOPEN
		}
		return &xtsFile{File: file, cipher: f.cipher}, flags, nil
	}

	var key []byte
	switch params := name.URIParameters(); {
	case name == nil:
		// Temporary files get a random key.
		key = kdf("")

	case len(params["key"]) > 0:
		key = []byte(params["key"][0])

	case len(params["hexkey"]) > 0:
		key, err = hex.DecodeString(params["hexkey"][0])
		if err != nil {
			return nil, flags, fmt.Errorf("error decoding hex key: %w", err)
		}

	case len(params["textkey"]) > 0:
		key = kdf(params["textkey"][0])

	case flags&vfs.OPEN_MAIN_DB != 0:
		// Main databases may have their key specified as a PRAGMA.
		return &xtsFile{File: file, name: name.String()}, flags, nil

	default:
		return nil, flags, sqlite3.CANTOPEN
	}

	cipher, err := newCipher(key)
	if err != nil {
		return nil, flags, sqlite3.CANTOPEN
	}

	return &xtsFile{
		File:   file,
		name:   name.String(),
		cipher: cipher,
	}, flags, nil
}

const blockSize = 4096

type xtsFile struct {
	vfs.File
	name string

	cipher *xts.Cipher

	block [blockSize]byte
}

func (x *xtsFile) Pragma(name string, value string) (string, error) {
	var key []byte
	switch name {
	case "key":
		key = []byte(value)
	case "hexkey":
		key, _ = hex.DecodeString(value)
	case "textkey":
		key = kdf(value)
	default:
		if f, ok := x.File.(vfs.FilePragma); ok {
			return f.Pragma(name, value)
		}
		return "", sqlite3.NOTFOUND
	}

	var err error
	if x.cipher, err = newCipher(key); err != nil {
		return "", sqlite3.CANTOPEN
	}
	return "ok", nil
}

func (x *xtsFile) ReadAt(p []byte, off int64) (n int, err error) {
	if x.cipher == nil {
		// Only OPEN_MAIN_DB can have a missing key.
		if off == 0 && len(p) == 100 {
			// SQLite is trying to read the header of a database file. Pretend the file is empty so
			// the key may specified as a PRAGMA.
			return 0, io.EOF
		}
		return 0, sqlite3.CANTOPEN
	}

	min := (off) &^ (blockSize - 1)                                   // round down
	max := (off + int64(len(p)) + (blockSize - 1)) &^ (blockSize - 1) // round up

	// Read one block at a time.
	for ; min < max; min += blockSize {
		m, err := x.File.ReadAt(x.block[:], min)
		if m != blockSize {
			return n, err
		}

		// Decrypt the entire block in place
		sectorNum := uint64(min / blockSize) //nolint:gosec
		x.cipher.Decrypt(x.block[:], x.block[:], sectorNum)

		// Append the block contents, starting from partial-block offset if applicable
		if off > min {
			n += copy(p[n:], x.block[off-min:])
			continue
		}
		n += copy(p[n:], x.block[:])
	}

	if n != len(p) {
		panic("unexpected EOF - should have failed at File.ReadAt or p was not a sized correctly")
	}
	return n, nil
}

func (x *xtsFile) WriteAt(p []byte, off int64) (n int, err error) {
	if x.cipher == nil {
		return 0, sqlite3.READONLY
	}

	min := (off) &^ (blockSize - 1)                                   // round down
	max := (off + int64(len(p)) + (blockSize - 1)) &^ (blockSize - 1) // round up

	// Write one block at a time.
	for ; min < max; min += blockSize {
		data := x.block[:]

		// Perform a partial write if offset is not at a block boundary or the length isn't a
		// complete block.
		if off > min || len(p[n:]) < blockSize {
			// Read the current block
			m, err := x.File.ReadAt(x.block[:], min)

			// Error on a partial read of the block, unless the end of the file was reached, in
			// which case this will be an append operation.
			if m != blockSize {
				if !errors.Is(err, io.EOF) {
					return n, err
				}

				// We're either appending an entirely new block, or the final block was only
				// partially written. A partially written block can't be decrypted, and is as good
				// as corrupt. Either way, zero pad the file to the next block size.
				clear(data)
			}

			// Upon reading a full block, decrypt it so that plaintext may be appended and the
			// whole block can be encrypted.
			if m == blockSize {
				sectorNum := uint64(min / blockSize) //nolint:gosec
				x.cipher.Decrypt(data, data, sectorNum)
			}

			// If writing from an offset, remove the data prior to the offset.
			if off > min {
				data = data[off-min:]
			}
		}

		// Copy into data, which may be a partial block
		written := copy(data, p[n:])

		// Encrypt the full block in place
		sectorNum := uint64(min / blockSize) //nolint:gosec
		x.cipher.Encrypt(x.block[:], x.block[:], sectorNum)

		// Write encrypted block to file
		m, err := x.File.WriteAt(x.block[:], min)
		if m != blockSize {
			return n, err
		}
		n += written
	}

	if n != len(p) {
		panic("incomplete write - should have failed due to a partial read or partial write of the underlying file")
	}
	return n, nil
}

func (x *xtsFile) Truncate(size int64) error {
	size = (size + (blockSize - 1)) &^ (blockSize - 1) // round up
	return x.File.Truncate(size)
}

func (x *xtsFile) SectorSize() int {
	return lcm(x.File.SectorSize(), blockSize)
}

func (x *xtsFile) DeviceCharacteristics() vfs.DeviceCharacteristic {
	return x.File.DeviceCharacteristics() & (0 |
		// The only safe flags are these:
		vfs.IOCAP_UNDELETABLE_WHEN_OPEN |
		vfs.IOCAP_IMMUTABLE |
		vfs.IOCAP_BATCH_ATOMIC)
}

// Wrap optional methods.

func (x *xtsFile) SharedMemory() vfs.SharedMemory {
	if f, ok := x.File.(vfs.FileSharedMemory); ok {
		return f.SharedMemory()
	}
	return nil
}

func (x *xtsFile) ChunkSize(size int) {
	if f, ok := x.File.(vfs.FileChunkSize); ok {
		size = (size + (blockSize - 1)) &^ (blockSize - 1) // round up
		f.ChunkSize(size)
	}
}

func (x *xtsFile) SizeHint(size int64) error {
	if f, ok := x.File.(vfs.FileSizeHint); ok {
		size = (size + (blockSize - 1)) &^ (blockSize - 1) // round up
		return f.SizeHint(size)
	}
	return sqlite3.NOTFOUND
}

func (x *xtsFile) HasMoved() (bool, error) {
	if f, ok := x.File.(vfs.FileHasMoved); ok {
		return f.HasMoved()
	}
	return false, sqlite3.NOTFOUND
}

func (x *xtsFile) Overwrite() error {
	if f, ok := x.File.(vfs.FileOverwrite); ok {
		return f.Overwrite()
	}
	return sqlite3.NOTFOUND
}

func (x *xtsFile) CommitPhaseTwo() error {
	if f, ok := x.File.(vfs.FileCommitPhaseTwo); ok {
		return f.CommitPhaseTwo()
	}
	return sqlite3.NOTFOUND
}

func (x *xtsFile) BeginAtomicWrite() error {
	if f, ok := x.File.(vfs.FileBatchAtomicWrite); ok {
		return f.BeginAtomicWrite()
	}
	return sqlite3.NOTFOUND
}

func (x *xtsFile) CommitAtomicWrite() error {
	if f, ok := x.File.(vfs.FileBatchAtomicWrite); ok {
		return f.CommitAtomicWrite()
	}
	return sqlite3.NOTFOUND
}

func (x *xtsFile) RollbackAtomicWrite() error {
	if f, ok := x.File.(vfs.FileBatchAtomicWrite); ok {
		return f.RollbackAtomicWrite()
	}
	return sqlite3.NOTFOUND
}

func (x *xtsFile) CheckpointDone() error {
	if f, ok := x.File.(vfs.FileCheckpoint); ok {
		return f.CheckpointDone()
	}
	return sqlite3.NOTFOUND
}

func (x *xtsFile) CheckpointStart() error {
	if f, ok := x.File.(vfs.FileCheckpoint); ok {
		return f.CheckpointStart()
	}
	return sqlite3.NOTFOUND
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func gcd(m, n int) int {
	for n != 0 {
		m, n = n, m%n
	}
	return abs(m)
}

func lcm(m, n int) int {
	if n == 0 {
		return 0
	}
	return abs(n) * (abs(m) / gcd(m, n))
}
