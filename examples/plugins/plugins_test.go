// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package plugins_test

import (
	"os"
	"os/exec"
	"testing"

	"github.com/fido-device-onboard/go-fdo/fdotest"
	"github.com/fido-device-onboard/go-fdo/fsim"
	"github.com/fido-device-onboard/go-fdo/plugin"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

func TestDownloadOwnerPlugin(t *testing.T) {
	downloadOwnerPlugin := &plugin.OwnerModule{
		Module: plugin.NewCommandPluginModule(exec.Command("./download_owner.bash", "go.mod")),
	}

	fdotest.RunClientTestSuite(t, nil, map[string]serviceinfo.DeviceModule{
		"fdo.download": &fsim.Download{
			CreateTemp: func() (*os.File, error) {
				return os.CreateTemp(".", "fdo.download_*")
			},
		},
	}, func(yield func(string, serviceinfo.OwnerModule) bool) {
		if !yield("fdo.download", downloadOwnerPlugin) {
			return
		}
	}, nil)
}
