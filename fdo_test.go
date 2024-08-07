// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo_test

import (
	"testing"
	"time"

	"github.com/fido-device-onboard/go-fdo/fdotest"
	"github.com/fido-device-onboard/go-fdo/plugin"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

const mockModuleName = "fdotest.mock"

func TestClient(t *testing.T) {
	fdotest.RunClientTestSuite(t, nil, nil, nil)
}

func TestClientWithPluginModule(t *testing.T) {
	devicePlugin, ownerPlugin := new(fdotest.MockPlugin), new(fdotest.MockPlugin)

	fdotest.RunClientTestSuite(t, nil, map[string]serviceinfo.DeviceModule{
		mockModuleName: struct {
			plugin.Module
			serviceinfo.DeviceModule
		}{
			Module:       devicePlugin,
			DeviceModule: &fdotest.MockDeviceModule{},
		},
	}, []serviceinfo.OwnerModule{
		struct {
			plugin.Module
			serviceinfo.OwnerModule
		}{
			Module:      ownerPlugin,
			OwnerModule: &fdotest.MockOwnerModule{},
		},
	})

	if !devicePlugin.GracefulStopped {
		t.Error("expected device plugin to be gracefully stopped")
	}
	if !devicePlugin.Stopped {
		t.Error("expected device plugin to be forcefully stopped")
	}

	// Owner plugins are stopped in separate goroutines and need time to
	// complete
	time.Sleep(300 * time.Millisecond)

	if !ownerPlugin.GracefulStopped {
		t.Error("expected owner plugin to be gracefully stopped")
	}
	if !ownerPlugin.Stopped {
		t.Error("expected owner plugin to be forcefully stopped")
	}
}

func TestServerState(t *testing.T) {
	fdotest.RunServerStateSuite(t, nil)
}
