// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestMoveFile tests same-filesystem move (os.Rename fast path)
func TestMoveFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create source file with specific permissions
	srcPath := filepath.Join(tmpDir, "source.txt")
	testContent := []byte("test content")
	if err := os.WriteFile(srcPath, testContent, 0640); err != nil {
		t.Fatalf("failed to create source file: %v", err)
	}

	dstPath := filepath.Join(tmpDir, "destination.txt")

	// Move file (same filesystem - uses os.Rename)
	if err := moveFile(srcPath, dstPath); err != nil {
		t.Fatalf("moveFile failed: %v", err)
	}

	// Verify source is gone
	if _, err := os.Stat(srcPath); !os.IsNotExist(err) {
		t.Errorf("source file still exists after move")
	}

	// Verify destination has correct content
	gotContent, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatalf("failed to read destination: %v", err)
	}

	if string(gotContent) != string(testContent) {
		t.Errorf("content mismatch: got %q, want %q", gotContent, testContent)
	}

	// Verify permissions preserved
	info, err := os.Stat(dstPath)
	if err != nil {
		t.Fatalf("failed to stat destination: %v", err)
	}

	if info.Mode().Perm() != 0640 {
		t.Errorf("permissions not preserved: got %o, want 0640", info.Mode().Perm())
	}
}

// TestMoveFileCrossFilesystem tests moveFile across different filesystems
func TestMoveFileCrossFilesystem(t *testing.T) {
	// Common filesystem pairs on Linux systems
	fsPairs := []struct {
		src  string
		dst  string
		desc string
	}{
		{"/tmp", "/var/tmp", "tmpfs to disk"},
		{"/tmp", ".", "tmpfs to current directory"},
		{"/dev/shm", "/tmp", "shared memory to tmpfs"},
	}

	var srcBase, dstBase string
	foundDifferent := false

	// Find two different filesystems
	for _, pair := range fsPairs {
		// Check both paths exist
		if _, err := os.Stat(pair.src); err != nil {
			continue
		}
		if _, err := os.Stat(pair.dst); err != nil {
			continue
		}

		// Check if on different filesystems
		var stat1, stat2 syscall.Stat_t
		if err := syscall.Stat(pair.src, &stat1); err != nil {
			continue
		}
		if err := syscall.Stat(pair.dst, &stat2); err != nil {
			continue
		}

		if stat1.Dev != stat2.Dev {
			srcBase = pair.src
			dstBase = pair.dst
			foundDifferent = true
			t.Logf("Testing cross-filesystem move: %s", pair.desc)
			break
		}
	}

	if !foundDifferent {
		t.Skip("No different filesystems found. Test requires RHEL/Fedora with tmpfs /tmp")
	}

	// Create source file
	srcFile, err := os.CreateTemp(srcBase, "fsim_test_src_*")
	if err != nil {
		t.Fatalf("failed to create source: %v", err)
	}
	srcPath := srcFile.Name()
	defer os.Remove(srcPath)

	testContent := []byte("cross-filesystem test")
	if _, err := srcFile.Write(testContent); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	srcFile.Close()

	// Set permissions to verify preservation
	if err := os.Chmod(srcPath, 0640); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}

	// Create destination path on different filesystem
	dstFile, err := os.CreateTemp(dstBase, "fsim_test_dst_*")
	if err != nil {
		t.Fatalf("failed to create dest: %v", err)
	}
	dstPath := dstFile.Name()
	dstFile.Close()
	os.Remove(dstPath) // Remove it, we just need the path
	defer os.Remove(dstPath)

	// Move file across filesystems
	if err := moveFile(srcPath, dstPath); err != nil {
		t.Fatalf("moveFile failed: %v", err)
	}

	// Verify source removed
	if _, err := os.Stat(srcPath); !os.IsNotExist(err) {
		t.Error("source still exists after move")
	}

	// Verify destination content
	got, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatalf("read dest failed: %v", err)
	}
	if string(got) != string(testContent) {
		t.Errorf("content mismatch: got %q, want %q", got, testContent)
	}

	// Verify permissions preserved
	info, err := os.Stat(dstPath)
	if err != nil {
		t.Fatalf("stat dest failed: %v", err)
	}
	if info.Mode().Perm() != 0640 {
		t.Errorf("permissions not preserved: got %o, want 0640", info.Mode().Perm())
	}
}
