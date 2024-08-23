// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fsim_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"iter"
	"log"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/fido-device-onboard/go-fdo"
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
