// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package fsim implements common FSIM modules defined in
// https://github.com/fido-alliance/fdo-sim/tree/main/fsim-repository as well
// as plugin modules as defined in plugin/README.md.
package fsim

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"syscall"
)

func debugEnabled() bool {
	return slog.Default().Enabled(context.Background(), slog.LevelDebug)
}

// moveFile moves a file from src to dst, using efficient os.Rename when
// possible, and falling back to io.Copy for cross-filesystem moves.
// This supports architectures like RHEL/Fedora where /tmp is on tmpfs
// (a separate RAM-based filesystem) while target directories are on disk.
func moveFile(src, dst string) error {
	// Try efficient rename first (works when src and dst are on same filesystem)
	err := os.Rename(src, dst)
	if err == nil {
		return nil
	}

	// Check if error is due to cross-filesystem move
	var linkErr *os.LinkError
	if errors.As(err, &linkErr) && errors.Is(linkErr.Err, syscall.EXDEV) {
		// Fall back to copy + remove for cross-filesystem move
		return copyAndRemove(src, dst)
	}

	// Return original error if not a cross-filesystem issue
	return err
}

// copyAndRemove copies src to dst and removes src on success.
func copyAndRemove(src, dst string) error {
	// Open source file
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("error opening source file: %w", err)
	}
	defer srcFile.Close()

	// Get source file permissions
	srcInfo, err := srcFile.Stat()
	if err != nil {
		return fmt.Errorf("error getting source file info: %w", err)
	}

	// Create destination file with same permissions as source
	dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return fmt.Errorf("error creating destination file: %w", err)
	}

	// Copy file contents
	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		_ = dstFile.Close()
		_ = os.Remove(dst) // Clean up partial file
		return fmt.Errorf("error copying file: %w", err)
	}

	// Sync to ensure data is written to disk
	if err = dstFile.Sync(); err != nil {
		_ = dstFile.Close()
		_ = os.Remove(dst) // Clean up
		return fmt.Errorf("error syncing destination file: %w", err)
	}

	// Close destination file
	if err = dstFile.Close(); err != nil {
		_ = os.Remove(dst) // Clean up
		return fmt.Errorf("error closing destination file: %w", err)
	}

	// Remove source file after successful copy
	if err = os.Remove(src); err != nil {
		return fmt.Errorf("error removing source file after copy: %w", err)
	}

	return nil
}
