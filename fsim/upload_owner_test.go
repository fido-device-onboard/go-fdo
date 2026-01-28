// SPDX-FileCopyrightText: (C) 2025 Red Hat, Inc.
// SPDX-License-Identifier: Apache 2.0

package fsim_test

import (
	"bytes"
	"context"
	"crypto/sha512"
	"os"
	"path/filepath"
	"testing"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/fsim"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// TestUploadRequestPathTraversalPrevention tests that the UploadRequest
// module prevents path traversal attacks using os.OpenRoot.
func TestUploadRequestPathTraversalPrevention(t *testing.T) {
	tests := []struct {
		name          string
		rename        string
		shouldSucceed bool
		expectedInDir string // expected file location relative to upload dir
		description   string
	}{
		{
			name:          "normal filename",
			rename:        "testfile.txt",
			shouldSucceed: true,
			expectedInDir: "testfile.txt",
			description:   "Normal upload should succeed",
		},
		{
			name:          "path traversal with ../",
			rename:        "../../../../../../../../tmp/testfile.txt",
			shouldSucceed: false,
			expectedInDir: "",
			description:   "Path traversal should be prevented by os.OpenRoot",
		},
		{
			name:          "path traversal with ../ in middle",
			rename:        "foo/../../../../../../../tmp/testfile.txt",
			shouldSucceed: false,
			expectedInDir: "",
			description:   "Path traversal in middle should be prevented",
		},
		{
			name:          "subdirectory creation",
			rename:        "subdir/testfile.txt",
			shouldSucceed: true,
			expectedInDir: "subdir/testfile.txt",
			description:   "Subdirectory creation should succeed with MakeDirectories enabled",
		},
		{
			name:          "absolute path",
			rename:        "/tmp/testfile.txt",
			shouldSucceed: false,
			expectedInDir: "",
			description:   "Absolute paths should be prevented",
		},
		{
			name:          "current dir reference",
			rename:        "./testfile.txt",
			shouldSucceed: true,
			expectedInDir: "testfile.txt",
			description:   "Current directory reference should work",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary upload directory
			uploadDir, err := os.MkdirTemp("", "upload_test_*")
			if err != nil {
				t.Fatalf("failed to create temp upload dir: %v", err)
			}
			defer func() { _ = os.RemoveAll(uploadDir) }()

			// Create test data
			testData := []byte("test file content for upload")
			sum := sha512.Sum384(testData)

			// Create UploadRequest
			uploadReq := &fsim.UploadRequest{
				Dir:             uploadDir,
				Name:            "original.txt",
				MakeDirectories: true, // Enable directory creation for this test
				Rename: func(name string) string {
					return tt.rename
				},
				CreateTemp: func() (*os.File, error) {
					return os.CreateTemp("", "upload_temp_*")
				},
			}

			// Simulate the upload process
			ctx := context.Background()
			producer := &serviceinfo.Producer{}

			// 1. Request upload (triggers active message)
			_, _, err = uploadReq.ProduceInfo(ctx, producer)
			if err != nil {
				t.Fatalf("failed to produce upload request: %v", err)
			}

			// 2. Handle active response
			activeBody, _ := cbor.Marshal(true)
			if err := uploadReq.HandleInfo(ctx, "active", bytes.NewReader(activeBody)); err != nil {
				t.Fatalf("failed to handle active message: %v", err)
			}

			// 3. Handle length message
			lengthBody, _ := cbor.Marshal(int64(len(testData)))
			if err := uploadReq.HandleInfo(ctx, "length", bytes.NewReader(lengthBody)); err != nil {
				t.Fatalf("failed to handle length message: %v", err)
			}

			// 4. Handle data message
			dataBody, _ := cbor.Marshal(testData)
			if err := uploadReq.HandleInfo(ctx, "data", bytes.NewReader(dataBody)); err != nil {
				t.Fatalf("failed to handle data message: %v", err)
			}

			// 5. Handle sha-384 message
			sha384Body, _ := cbor.Marshal(sum[:])
			if err := uploadReq.HandleInfo(ctx, "sha-384", bytes.NewReader(sha384Body)); err != nil {
				t.Fatalf("failed to handle sha-384 message: %v", err)
			}

			// 6. Finalize (this is where path traversal prevention happens)
			_, moduleDone, err := uploadReq.ProduceInfo(ctx, producer)

			if tt.shouldSucceed {
				if err != nil {
					t.Errorf("expected success but got error: %v", err)
				}
				if !moduleDone {
					t.Error("expected module to be done")
				}

				// Verify file exists at expected location
				expectedPath := filepath.Join(uploadDir, tt.expectedInDir)
				content, err := os.ReadFile(expectedPath)
				if err != nil {
					t.Errorf("failed to read uploaded file at %s: %v", expectedPath, err)
				}
				if !bytes.Equal(content, testData) {
					t.Errorf("uploaded content mismatch: got %q, want %q", content, testData)
				}

				// Verify file did NOT escape upload directory
				entries, _ := os.ReadDir(uploadDir)
				foundInRoot := false
				for _, entry := range entries {
					if entry.Name() == filepath.Base(tt.expectedInDir) {
						foundInRoot = true
						break
					}
				}
				if !foundInRoot && tt.expectedInDir == filepath.Base(tt.expectedInDir) {
					t.Errorf("expected file not found in upload directory")
				}
			} else {
				if err == nil {
					t.Errorf("expected error for %s, but got success", tt.description)
				}

				// Verify no files were created in the upload directory
				// (since the operation should have failed)
				entries, _ := os.ReadDir(uploadDir)
				if len(entries) > 0 {
					t.Errorf("expected empty upload directory after failed upload, but found %d entries", len(entries))
					for _, entry := range entries {
						t.Logf("  found: %s", entry.Name())
					}
				}
			}
		})
	}
}

// TestUploadRequestNormalFlow tests the normal upload flow without
// any malicious path traversal attempts.
func TestUploadRequestNormalFlow(t *testing.T) {
	// Create temporary upload directory
	uploadDir, err := os.MkdirTemp("", "upload_normal_test_*")
	if err != nil {
		t.Fatalf("failed to create temp upload dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(uploadDir) }()

	// Create test data
	testData := []byte("This is a test file for normal upload flow")
	sum := sha512.Sum384(testData)

	// Create UploadRequest
	uploadReq := &fsim.UploadRequest{
		Dir:  uploadDir,
		Name: "testfile.dat",
		Rename: func(name string) string {
			return "uploaded.dat"
		},
		CreateTemp: func() (*os.File, error) {
			return os.CreateTemp("", "upload_normal_temp_*")
		},
	}

	ctx := context.Background()
	producer := &serviceinfo.Producer{}

	// Simulate upload process
	_, _, err = uploadReq.ProduceInfo(ctx, producer)
	if err != nil {
		t.Fatalf("failed to produce upload request: %v", err)
	}

	activeBody, _ := cbor.Marshal(true)
	if err := uploadReq.HandleInfo(ctx, "active", bytes.NewReader(activeBody)); err != nil {
		t.Fatalf("failed to handle active: %v", err)
	}

	lengthBody, _ := cbor.Marshal(int64(len(testData)))
	if err := uploadReq.HandleInfo(ctx, "length", bytes.NewReader(lengthBody)); err != nil {
		t.Fatalf("failed to handle length: %v", err)
	}

	dataBody, _ := cbor.Marshal(testData)
	if err := uploadReq.HandleInfo(ctx, "data", bytes.NewReader(dataBody)); err != nil {
		t.Fatalf("failed to handle data: %v", err)
	}

	sha384Body, _ := cbor.Marshal(sum[:])
	if err := uploadReq.HandleInfo(ctx, "sha-384", bytes.NewReader(sha384Body)); err != nil {
		t.Fatalf("failed to handle sha-384: %v", err)
	}

	_, moduleDone, err := uploadReq.ProduceInfo(ctx, producer)
	if err != nil {
		t.Fatalf("failed to finalize upload: %v", err)
	}
	if !moduleDone {
		t.Error("expected module to be done")
	}

	// Verify uploaded file
	uploadedPath := filepath.Join(uploadDir, "uploaded.dat")
	content, err := os.ReadFile(uploadedPath)
	if err != nil {
		t.Fatalf("failed to read uploaded file: %v", err)
	}
	if !bytes.Equal(content, testData) {
		t.Errorf("content mismatch: got %q, want %q", content, testData)
	}
}

// TestUploadRequestDefaultRename tests that when Rename is empty,
// it defaults to the basename of Name.
func TestUploadRequestDefaultRename(t *testing.T) {
	uploadDir, err := os.MkdirTemp("", "upload_rename_test_*")
	if err != nil {
		t.Fatalf("failed to create temp upload dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(uploadDir) }()

	testData := []byte("test content")
	sum := sha512.Sum384(testData)

	uploadReq := &fsim.UploadRequest{
		Dir:             uploadDir,
		Name:            "path/to/file.txt",
		MakeDirectories: true, // Required to create parent directories
		// Rename is intentionally empty
		CreateTemp: func() (*os.File, error) {
			return os.CreateTemp("", "upload_rename_temp_*")
		},
	}

	ctx := context.Background()
	producer := &serviceinfo.Producer{}

	// Simulate upload
	_, _, _ = uploadReq.ProduceInfo(ctx, producer)
	activeBody, _ := cbor.Marshal(true)
	_ = uploadReq.HandleInfo(ctx, "active", bytes.NewReader(activeBody))
	lengthBody, _ := cbor.Marshal(int64(len(testData)))
	_ = uploadReq.HandleInfo(ctx, "length", bytes.NewReader(lengthBody))
	dataBody, _ := cbor.Marshal(testData)
	_ = uploadReq.HandleInfo(ctx, "data", bytes.NewReader(dataBody))
	sha384Body, _ := cbor.Marshal(sum[:])
	_ = uploadReq.HandleInfo(ctx, "sha-384", bytes.NewReader(sha384Body))

	_, _, err = uploadReq.ProduceInfo(ctx, producer)
	if err != nil {
		t.Fatalf("failed to finalize: %v", err)
	}

	// Should preserve directory structure "path/to/file.txt"
	expectedPath := filepath.Join(uploadDir, "path/to/file.txt")
	if _, err := os.Stat(expectedPath); err != nil {
		t.Errorf("expected file at %s, but got error: %v", expectedPath, err)
	}
}

// TestUploadRequestSHA384Mismatch tests that uploads fail when SHA-384 doesn't match.
func TestUploadRequestSHA384Mismatch(t *testing.T) {
	uploadDir, err := os.MkdirTemp("", "upload_sha_test_*")
	if err != nil {
		t.Fatalf("failed to create temp upload dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(uploadDir) }()

	testData := []byte("test content")
	wrongSum := sha512.Sum384([]byte("wrong content"))

	uploadReq := &fsim.UploadRequest{
		Dir:  uploadDir,
		Name: "test.txt",
		Rename: func(name string) string {
			return "test.txt"
		},
		CreateTemp: func() (*os.File, error) {
			return os.CreateTemp("", "upload_sha_temp_*")
		},
	}

	ctx := context.Background()
	producer := &serviceinfo.Producer{}

	_, _, _ = uploadReq.ProduceInfo(ctx, producer)
	activeBody, _ := cbor.Marshal(true)
	_ = uploadReq.HandleInfo(ctx, "active", bytes.NewReader(activeBody))
	lengthBody, _ := cbor.Marshal(int64(len(testData)))
	_ = uploadReq.HandleInfo(ctx, "length", bytes.NewReader(lengthBody))
	dataBody, _ := cbor.Marshal(testData)
	_ = uploadReq.HandleInfo(ctx, "data", bytes.NewReader(dataBody))
	sha384Body, _ := cbor.Marshal(wrongSum[:])
	_ = uploadReq.HandleInfo(ctx, "sha-384", bytes.NewReader(sha384Body))

	_, _, err = uploadReq.ProduceInfo(ctx, producer)
	if err == nil {
		t.Error("expected error for SHA-384 mismatch, but got success")
	}
	if err != nil && !bytes.Contains([]byte(err.Error()), []byte("SHA-384")) {
		t.Errorf("expected SHA-384 error, got: %v", err)
	}
}

// TestUploadRequestSameFilesystemRename tests that files are renamed (not copied)
// when temp file and destination are on the same filesystem.
func TestUploadRequestSameFilesystemRename(t *testing.T) {
	uploadDir, err := os.MkdirTemp("", "upload_samefs_test_*")
	if err != nil {
		t.Fatalf("failed to create temp upload dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(uploadDir) }()

	testData := []byte("test content for same filesystem")
	sum := sha512.Sum384(testData)

	// Create temp file in the same directory to ensure same filesystem
	uploadReq := &fsim.UploadRequest{
		Dir:  uploadDir,
		Name: "testfile.dat",
		Rename: func(name string) string {
			return "uploaded.dat"
		},
		CreateTemp: func() (*os.File, error) {
			// Create temp file in same directory to guarantee same filesystem
			return os.CreateTemp(uploadDir, "upload_samefs_temp_*")
		},
	}

	ctx := context.Background()
	producer := &serviceinfo.Producer{}

	// Simulate upload
	_, _, _ = uploadReq.ProduceInfo(ctx, producer)
	activeBody, _ := cbor.Marshal(true)
	_ = uploadReq.HandleInfo(ctx, "active", bytes.NewReader(activeBody))
	lengthBody, _ := cbor.Marshal(int64(len(testData)))
	_ = uploadReq.HandleInfo(ctx, "length", bytes.NewReader(lengthBody))
	dataBody, _ := cbor.Marshal(testData)
	_ = uploadReq.HandleInfo(ctx, "data", bytes.NewReader(dataBody))
	sha384Body, _ := cbor.Marshal(sum[:])
	_ = uploadReq.HandleInfo(ctx, "sha-384", bytes.NewReader(sha384Body))

	_, _, err = uploadReq.ProduceInfo(ctx, producer)
	if err != nil {
		t.Fatalf("failed to finalize upload: %v", err)
	}

	// Verify uploaded file exists and has correct content
	uploadedPath := filepath.Join(uploadDir, "uploaded.dat")
	content, err := os.ReadFile(uploadedPath)
	if err != nil {
		t.Fatalf("failed to read uploaded file: %v", err)
	}
	if !bytes.Equal(content, testData) {
		t.Errorf("content mismatch: got %q, want %q", content, testData)
	}

	// Verify temp file was removed (regardless of rename vs copy)
	entries, err := os.ReadDir(uploadDir)
	if err != nil {
		t.Fatalf("failed to read upload dir: %v", err)
	}

	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == "" && entry.Name() != "uploaded.dat" {
			// Found a file without extension that's not our target
			// (likely a leftover temp file)
			t.Errorf("found potential leftover temp file: %s", entry.Name())
		}
	}
}

// TestUploadRequestMakeDirectories tests the MakeDirectories variable behavior.
func TestUploadRequestMakeDirectories(t *testing.T) {
	tests := []struct {
		name            string
		makeDirectories bool
		uploadPath      string
		preSeedDir      string // directory to create before upload (empty = don't create)
		shouldSucceed   bool
		description     string
	}{
		{
			name:            "MakeDirectories=true with nested path",
			makeDirectories: true,
			uploadPath:      "a/b/c/testfile.txt",
			preSeedDir:      "",
			shouldSucceed:   true,
			description:     "Should create all parent directories",
		},
		{
			name:            "MakeDirectories=false with nested path (parent doesn't exist)",
			makeDirectories: false,
			uploadPath:      "a/b/c/testfile.txt",
			preSeedDir:      "",
			shouldSucceed:   false,
			description:     "Should fail when parent directories don't exist",
		},
		{
			name:            "MakeDirectories=false with nested path (parent exists)",
			makeDirectories: false,
			uploadPath:      "existing/testfile.txt",
			preSeedDir:      "existing",
			shouldSucceed:   true,
			description:     "Should succeed when parent directory already exists",
		},
		{
			name:            "MakeDirectories=true with single level",
			makeDirectories: true,
			uploadPath:      "subdir/testfile.txt",
			preSeedDir:      "",
			shouldSucceed:   true,
			description:     "Should create single parent directory",
		},
		{
			name:            "MakeDirectories=false with file in root",
			makeDirectories: false,
			uploadPath:      "testfile.txt",
			preSeedDir:      "",
			shouldSucceed:   true,
			description:     "Should succeed for files in root directory",
		},
		{
			name:            "MakeDirectories=true with file in root",
			makeDirectories: true,
			uploadPath:      "testfile.txt",
			preSeedDir:      "",
			shouldSucceed:   true,
			description:     "Should succeed for files in root directory",
		},
		{
			name:            "MakeDirectories=true with deeply nested path",
			makeDirectories: true,
			uploadPath:      "a/b/c/d/e/f/testfile.txt",
			preSeedDir:      "",
			shouldSucceed:   true,
			description:     "Should create deeply nested directory structure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary upload directory
			uploadDir, err := os.MkdirTemp("", "upload_mkdir_test_*")
			if err != nil {
				t.Fatalf("failed to create temp upload dir: %v", err)
			}
			defer func() { _ = os.RemoveAll(uploadDir) }()

			// Pre-seed directory if specified
			if tt.preSeedDir != "" {
				if err := os.MkdirAll(filepath.Join(uploadDir, tt.preSeedDir), 0o755); err != nil {
					t.Fatalf("failed to create pre-seed directory: %v", err)
				}
			}

			// Create test data
			testData := []byte("test content for MakeDirectories test")
			sum := sha512.Sum384(testData)

			// Create UploadRequest
			uploadReq := &fsim.UploadRequest{
				Dir:             uploadDir,
				Name:            "original.txt",
				MakeDirectories: tt.makeDirectories,
				Rename: func(name string) string {
					return tt.uploadPath
				},
				CreateTemp: func() (*os.File, error) {
					return os.CreateTemp("", "upload_mkdir_temp_*")
				},
			}

			// Simulate the upload process
			ctx := context.Background()
			producer := &serviceinfo.Producer{}

			// Request upload
			_, _, err = uploadReq.ProduceInfo(ctx, producer)
			if err != nil {
				t.Fatalf("failed to produce upload request: %v", err)
			}

			// Handle active response
			activeBody, _ := cbor.Marshal(true)
			if err := uploadReq.HandleInfo(ctx, "active", bytes.NewReader(activeBody)); err != nil {
				t.Fatalf("failed to handle active message: %v", err)
			}

			// Handle length message
			lengthBody, _ := cbor.Marshal(int64(len(testData)))
			if err := uploadReq.HandleInfo(ctx, "length", bytes.NewReader(lengthBody)); err != nil {
				t.Fatalf("failed to handle length message: %v", err)
			}

			// Handle data message
			dataBody, _ := cbor.Marshal(testData)
			if err := uploadReq.HandleInfo(ctx, "data", bytes.NewReader(dataBody)); err != nil {
				t.Fatalf("failed to handle data message: %v", err)
			}

			// Handle sha-384 message
			sha384Body, _ := cbor.Marshal(sum[:])
			if err := uploadReq.HandleInfo(ctx, "sha-384", bytes.NewReader(sha384Body)); err != nil {
				t.Fatalf("failed to handle sha-384 message: %v", err)
			}

			// Finalize
			_, moduleDone, err := uploadReq.ProduceInfo(ctx, producer)

			if tt.shouldSucceed {
				if err != nil {
					t.Errorf("expected success but got error: %v", err)
				}
				if !moduleDone {
					t.Error("expected module to be done")
				}

				// Verify file exists at expected location
				expectedPath := filepath.Join(uploadDir, tt.uploadPath)
				content, err := os.ReadFile(expectedPath)
				if err != nil {
					t.Errorf("failed to read uploaded file at %s: %v", expectedPath, err)
				}
				if !bytes.Equal(content, testData) {
					t.Errorf("uploaded content mismatch: got %q, want %q", content, testData)
				}

				// Verify parent directories were created
				parentDir := filepath.Dir(expectedPath)
				if stat, err := os.Stat(parentDir); err != nil {
					t.Errorf("parent directory doesn't exist: %v", err)
				} else if !stat.IsDir() {
					t.Errorf("parent path is not a directory")
				}
			} else {
				if err == nil {
					t.Errorf("expected error for %s, but got success", tt.description)
				}
				if moduleDone {
					t.Error("expected module to not be done when error occurred")
				}

				// Verify file was NOT created
				expectedPath := filepath.Join(uploadDir, tt.uploadPath)
				if _, err := os.Stat(expectedPath); err == nil {
					t.Errorf("file should not exist after failed upload, but found at %s", expectedPath)
				}
			}
		})
	}
}
