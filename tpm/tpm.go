// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

//go:build !windows

// Package tpm implements device credentials using the
// [TPM Draft Spec](https://fidoalliance.org/specs/FDO/securing-fdo-in-tpm-v1.0-rd-20231010/securing-fdo-in-tpm-v1.0-rd-20231010.html).
package tpm

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// TPM represents a logical connection to a TPM.
type TPM interface {
	Send(input []byte) ([]byte, error)
}

// Closer represents a logical connection to a TPM and you can close it.
type Closer interface {
	TPM
	io.Closer
}

// OpenUnix opens a TPM device at the given path.
//
// Clients should use /dev/tpmrm0 because using /dev/tpm0 requires more
// extensive resource management that the kernel already handles for us
// when using the kernel resource manager.
func OpenUnix(path string) (Closer, error) {
	switch {
	case isDevNode(path, DevNodeManaged):
		return linuxtpm.Open(path)
	case isDevNode(path, DevNodeUnmanaged):
		slog.Warn("direct use of the TPM can lead to resource exhaustion, use a TPM resource manager instead")
		return linuxtpm.Open(path)
	default:
		return nil, fmt.Errorf("unsupported TPM device path: %s", path)
	}
}

// DevNodeKind enumerates managed and unmanaged TPM dev node kinds.
type DevNodeKind uint8

// PathPrefix returns the standard unix /dev node path without the numerical
// index.
func (n DevNodeKind) PathPrefix() string {
	switch n {
	case DevNodeUnmanaged:
		return "/dev/tpm"
	case DevNodeManaged:
		return "/dev/tpmrm"
	}
	panic("invalid TPM dev node kind")
}

const (
	// DevNodeUnmanaged is an unmanaged TPM resource which should not be used
	// by concurrent processes.
	DevNodeUnmanaged DevNodeKind = iota

	// DevNodeManaged is a kernel-managed TPM resource that is safe for
	// concurrent usage.
	DevNodeManaged
)

// IsDevNode checks that path is a device node at the standard unix path for
// kind.
func isDevNode(path string, kind DevNodeKind) bool {
	path = filepath.Clean(path)

	// Check path has appropriate prefix and numerical index
	prefix := kind.PathPrefix()
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	sIdx := strings.TrimPrefix(path, prefix)
	if _, err := strconv.ParseUint(sIdx, 10, 16); err != nil {
		return false
	}

	// Check that node exists and is an actual device node
	stat, err := os.Stat(path)
	if err != nil {
		return false
	}
	return stat.Mode().Type() == os.ModeDevice
}
