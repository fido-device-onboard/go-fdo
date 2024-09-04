// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fsim_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"iter"
	"log"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cbor/cdn"
	"github.com/fido-device-onboard/go-fdo/fdotest"
	"github.com/fido-device-onboard/go-fdo/fsim"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

func TestClient(t *testing.T) {
	if err := os.MkdirAll("testdata/downloads", 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("testdata/uploads", 0755); err != nil {
		t.Fatal(err)
	}

	data := bytes.Repeat([]byte("Hello World!\n"), 1024)

	fdotest.RunClientTestSuite(t, nil, map[string]serviceinfo.DeviceModule{
		"fdo.download": &fsim.Download{
			CreateTemp: func() (*os.File, error) {
				return os.CreateTemp("testdata", "fdo.download_*")
			},
			NameToPath: func(name string) string {
				return filepath.Join("testdata", "downloads", name)
			},
			ErrorLog: fdotest.TestingLog(t),
		},
		"fdo.upload": &fsim.Upload{FS: fstest.MapFS{
			"bigfile.test": &fstest.MapFile{
				Data: data,
				Mode: 0777,
			},
		}},
	}, func(ctx context.Context, replacementGUID fdo.GUID, info string, chain []*x509.Certificate, devmod fdo.Devmod, supportedMods []string) iter.Seq2[string, serviceinfo.OwnerModule] {
		return func(yield func(string, serviceinfo.OwnerModule) bool) {
			if !yield("fdo.download", &fsim.DownloadContents[*bytes.Reader]{
				Name:         "bigfile.test",
				Contents:     bytes.NewReader(data),
				MustDownload: true,
			}) {
				return
			}

			if !yield("fdo.upload", &fsim.UploadRequest{
				Dir:  "testdata/uploads",
				Name: "bigfile.test",
				CreateTemp: func() (*os.File, error) {
					return os.CreateTemp("testdata", "fdo.upload_*")
				},
			}) {
				return
			}
		}
	}, nil)

	/// Validate contents
	downloadContents, err := os.ReadFile("testdata/downloads/bigfile.test")
	if err != nil {
		log.Fatal(err)
	}
	if !bytes.Equal(downloadContents, data) {
		t.Fatal("download contents did not match expected")
	}
	uploadContents, err := os.ReadFile("testdata/uploads/bigfile.test")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(uploadContents, data) {
		t.Fatal("upload contents did not match expected")
	}
}

func TestClientWithMockDownloadOwner(t *testing.T) {
	const moduleName = "fdo.download"

	var (
		firstTime = true
		gotDone   = false
	)
	ownerModule := &fdotest.MockOwnerModule{
		ProduceInfoFunc: func(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
			if firstTime {
				firstTime = false

				if err := producer.WriteChunk(moduleName, "active",
					[]byte{0xf5}); err != nil {
					return false, false, err
				}
				if err := producer.WriteChunk(moduleName, "sha-384",
					[]byte{0x58, 0x30, 0x9c, 0xa3, 0x46, 0xe2, 0xd3,
						0x47, 0x94, 0x3f, 0xa6, 0xfe, 0x18, 0xb5, 0x33, 0x23, 0x76,
						0xa8, 0x28, 0x1a, 0xae, 0x7f, 0x92, 0x3c, 0x82, 0x37, 0xd3,
						0x83, 0x70, 0xcb, 0x78, 0xdf, 0x41, 0x7d, 0x41, 0x4e, 0x0f,
						0x38, 0x04, 0xfb, 0x89, 0x97, 0x00, 0x0e, 0x79, 0xcb, 0xd5,
						0xb7, 0xbe, 0xb4}); err != nil {
					return false, false, err
				}
				if err := producer.WriteChunk(moduleName, "length",
					[]byte{0x18, 0x1c}); err != nil {
					return false, false, err
				}
				if err := producer.WriteChunk(moduleName, "name",
					[]byte{0x67, 0x6e, 0x65, 0x77, 0x66, 0x69, 0x6c,
						0x65}); err != nil {
					return false, false, err
				}
				if err := producer.WriteChunk(moduleName, "data",
					[]byte{0x58, 0x1c, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69,
						0x73, 0x20, 0x61, 0x20, 0x6e, 0x65, 0x77, 0x20, 0x66, 0x69, 0x6c,
						0x65, 0x2c, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x53, 0x56, 0x49, 0x0a,
					}); err != nil {
					return false, false, err
				}
				if err := producer.WriteChunk(moduleName, "data",
					[]byte{0x40}); err != nil {
					return false, false, err
				}
			}
			return false, gotDone, nil
		},
		HandleInfoFunc: func(ctx context.Context, moduleName, messageName string, messageBody io.Reader) error {
			t.Logf("got message %q", messageName)
			body, err := io.ReadAll(messageBody)
			if err != nil {
				return fmt.Errorf("error reading message body: %s: %w", messageName, err)
			}
			t.Logf("got message %q body: %s", messageName, tryDebugNotation(body))
			if messageName == "done" {
				gotDone = true
				var result int64
				if err := cbor.Unmarshal(body, &result); err != nil {
					return err
				}
				if result < 0 {
					return fmt.Errorf("device module reported download failure to owner")
				}
				if result != 28 {
					return fmt.Errorf("device module did not download 28 bytes, got %d", result)
				}
			}
			return nil
		},
	}

	fdotest.RunClientTestSuite(t, nil, map[string]serviceinfo.DeviceModule{
		moduleName: &fsim.Download{
			CreateTemp: func() (*os.File, error) {
				return os.CreateTemp("testdata", "fdo.download_*")
			},
			NameToPath: func(name string) string {
				return filepath.Join("testdata", "downloads", name)
			},
			ErrorLog: fdotest.TestingLog(t),
		},
	}, func(ctx context.Context, replacementGUID fdo.GUID, info string, chain []*x509.Certificate, devmod fdo.Devmod, supportedMods []string) iter.Seq2[string, serviceinfo.OwnerModule] {
		return func(yield func(string, serviceinfo.OwnerModule) bool) {
			yield(moduleName, ownerModule)
		}
	}, nil)
}

func tryDebugNotation(b []byte) string {
	d, err := cdn.FromCBOR(b)
	if err != nil {
		return hex.EncodeToString(b)
	}
	return d
}
