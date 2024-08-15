// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package plugins_test

import (
	"bytes"
	"os"
	"os/exec"
	"testing"

	"github.com/fido-device-onboard/go-fdo/fdotest"
	"github.com/fido-device-onboard/go-fdo/fsim"
	"github.com/fido-device-onboard/go-fdo/plugin"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

func TestDownloadOwnerPlugin(t *testing.T) {
	if err := os.MkdirAll("testdata/downloads", 0755); err != nil {
		t.Fatal(err)
	}
	expected, err := os.ReadFile("testdata/bigfile")
	if err != nil {
		t.Fatal(err)
	}

	downloadOwnerPlugin := &plugin.OwnerModule{
		Module: plugin.NewCommandPluginModule(exec.Command("./download_owner.bash", "testdata/bigfile", "testdata/downloads/bigfile.test")),
	}

	fdotest.RunClientTestSuite(t, nil, map[string]serviceinfo.DeviceModule{
		"fdo.download": &fsim.Download{
			CreateTemp: func() (*os.File, error) {
				return os.CreateTemp(".", "fdo.download_*")
			},
			ErrorLog: fdotest.ErrorLog(t),
		},
	}, func(yield func(string, serviceinfo.OwnerModule) bool) {
		if !yield("fdo.download", downloadOwnerPlugin) {
			return
		}
	}, nil)

	// Validate expected contents
	downloadContents, err := os.ReadFile("testdata/downloads/bigfile.test")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(downloadContents, expected) {
		t.Fatal("download contents did not match expected")
	}
}
