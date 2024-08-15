// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package plugins_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/fido-device-onboard/go-fdo/fdotest"
	"github.com/fido-device-onboard/go-fdo/fsim"
	"github.com/fido-device-onboard/go-fdo/plugin"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

func TestDownloadOwnerPlugin(t *testing.T) {
	if err := os.RemoveAll("testdata/downloads"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("testdata/downloads", 0755); err != nil {
		t.Fatal(err)
	}
	expected, err := os.ReadFile("testdata/bigfile")
	if err != nil {
		t.Fatal(err)
	}

	downloadOwnerCmd := exec.Command("./download_owner.bash", "testdata/bigfile", "bigfile.test")
	downloadOwnerCmd.Stderr = fdotest.ErrorLog(t)
	downloadOwnerPlugin := &plugin.OwnerModule{Module: plugin.NewCommandPluginModule(downloadOwnerCmd)}

	fdotest.RunClientTestSuite(t, nil, map[string]serviceinfo.DeviceModule{
		"fdo.download": &fsim.Download{
			CreateTemp: func() (*os.File, error) {
				return os.CreateTemp(".", "fdo.download_*")
			},
			NameToPath: func(name string) string {
				return filepath.Join("testdata", "downloads", name)
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

func TestDownloadDevicePlugin(t *testing.T) {
	if err := os.RemoveAll("testdata/downloads"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("testdata/downloads", 0755); err != nil {
		t.Fatal(err)
	}

	expected := bytes.Repeat([]byte("Hello World!\n"), 1024)

	downloadDeviceCmd := exec.Command("./download_device.bash", "testdata/downloads")
	downloadDeviceCmd.Stderr = fdotest.ErrorLog(t)
	downloadDevicePlugin := &plugin.DeviceModule{Module: plugin.NewCommandPluginModule(downloadDeviceCmd)}

	fdotest.RunClientTestSuite(t, nil, map[string]serviceinfo.DeviceModule{
		"fdo.download": downloadDevicePlugin,
	}, func(yield func(string, serviceinfo.OwnerModule) bool) {
		if !yield("fdo.download", &fsim.DownloadContents[*bytes.Reader]{
			Name:         "bigfile.test",
			Contents:     bytes.NewReader(expected),
			MustDownload: true,
		}) {
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
