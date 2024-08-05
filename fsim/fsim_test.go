// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fsim_test

import (
	"bytes"
	"os"
	"testing"
	"testing/fstest"

	"github.com/fido-device-onboard/go-fdo/fdotest"
	"github.com/fido-device-onboard/go-fdo/fsim"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

func TestClient(t *testing.T) {
	fdotest.RunClientTestSuite(t, nil, map[string]serviceinfo.DeviceModule{
		"fdo.download": &fsim.Download{
			CreateTemp: func() (*os.File, error) {
				return os.CreateTemp(".", "fdo.download_*")
			},
		},
		"fdo.upload": &fsim.Upload{FS: fstest.MapFS{
			"bigfile.test": &fstest.MapFile{
				Data: bytes.Repeat([]byte("Hello World!\n"), 1024),
				Mode: 0777,
			},
		}},
	}, []serviceinfo.OwnerModule{
		&fsim.DownloadContents[*bytes.Reader]{
			Name:         "download.test",
			Contents:     bytes.NewReader([]byte("Hello world!")),
			MustDownload: true,
		},
		&fsim.UploadRequest{
			Dir:  ".",
			Name: "bigfile.test",
			CreateTemp: func() (*os.File, error) {
				return os.CreateTemp(".", "fdo.upload_*")
			},
		},
	})
}
