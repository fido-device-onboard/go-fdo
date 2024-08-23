// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package plugins_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"iter"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/fido-device-onboard/go-fdo"
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
	downloadOwnerCmd.Stderr = fdotest.TestingLog(t)
	downloadOwnerPlugin := &plugin.OwnerModule{Module: plugin.NewCommandPluginModule(downloadOwnerCmd)}

	fdotest.RunClientTestSuite(t, nil, map[string]serviceinfo.DeviceModule{
		"fdo.download": &fsim.Download{
			CreateTemp: func() (*os.File, error) {
				return os.CreateTemp(".", "fdo.download_*")
			},
			NameToPath: func(name string) string {
				return filepath.Join("testdata", "downloads", name)
			},
			ErrorLog: fdotest.TestingLog(t),
		},
	}, func(ctx context.Context, replacementGUID fdo.GUID, info string, chain []*x509.Certificate, devmod fdo.Devmod, supportedMods []string) iter.Seq2[string, serviceinfo.OwnerModule] {
		return func(yield func(string, serviceinfo.OwnerModule) bool) {
			if !yield("fdo.download", downloadOwnerPlugin) {
				return
			}
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
	downloadDeviceCmd.Stderr = fdotest.TestingLog(t)
	downloadDevicePlugin := &plugin.DeviceModule{Module: plugin.NewCommandPluginModule(downloadDeviceCmd)}

	fdotest.RunClientTestSuite(t, nil, map[string]serviceinfo.DeviceModule{
		"fdo.download": downloadDevicePlugin,
	}, func(ctx context.Context, replacementGUID fdo.GUID, info string, chain []*x509.Certificate, devmod fdo.Devmod, supportedMods []string) iter.Seq2[string, serviceinfo.OwnerModule] {
		return func(yield func(string, serviceinfo.OwnerModule) bool) {
			if !yield("fdo.download", &fsim.DownloadContents[*bytes.Reader]{
				Name:         "bigfile.test",
				Contents:     bytes.NewReader(expected),
				MustDownload: true,
			}) {
				return
			}
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

func TestDevmodPlugin(t *testing.T) {
	expected := fdo.Devmod{
		Os:      runtime.GOOS,
		Arch:    runtime.GOARCH,
		Version: "TestOS",
		Device:  "UnitMcUnitFace",
		Serial:  []byte{0x00, 0x01, 0x02, 0x04},
		PathSep: "/",
		FileSep: ";",
		Newline: "\n",
		Temp:    "/tmp",
		Dir:     "/home/fdo",
		ProgEnv: "bin:go",
		Bin:     runtime.GOARCH,
		MudURL:  "",
	}

	devmodCmd := exec.Command("./devmod.bash",
		expected.Os,
		expected.Arch,
		expected.Version,
		expected.Device,
		hex.EncodeToString(expected.Serial),
		expected.PathSep,
		expected.FileSep,
		expected.Newline,
		expected.Temp,
		expected.Dir,
		expected.ProgEnv,
		expected.Bin,
		expected.MudURL,
	)
	devmodCmd.Stderr = fdotest.TestingLog(t)
	devmodPlugin := &plugin.DeviceModule{Module: plugin.NewCommandPluginModule(devmodCmd)}

	var got fdo.Devmod

	fdotest.RunClientTestSuite(t, nil, map[string]serviceinfo.DeviceModule{
		"devmod": devmodPlugin,
	}, func(ctx context.Context, replacementGUID fdo.GUID, info string, chain []*x509.Certificate, devmod fdo.Devmod, supportedMods []string) iter.Seq2[string, serviceinfo.OwnerModule] {
		got = devmod
		return func(yield func(string, serviceinfo.OwnerModule) bool) {}
	}, nil)

	if !reflect.DeepEqual(got, expected) {
		t.Errorf("devmod did not match expected\nwant %+v\ngot  %+v", expected, got)
	}
}
