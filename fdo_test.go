// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo_test

import (
	"context"
	"io"
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

func TestClientWithMockModule(t *testing.T) {
	deviceModule := &fdotest.MockDeviceModule{
		ReceiveFunc: func(ctx context.Context, moduleName, messageName string, messageBody io.Reader, respond func(message string) io.Writer, yield func()) error {
			_, _ = io.Copy(io.Discard, messageBody)
			return nil
		},
	}
	ownerModule := &fdotest.MockOwnerModule{
		ProduceInfoFunc: func(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
			if err := producer.WriteChunk(mockModuleName, "active", []byte{0xf5}); err != nil {
				return false, false, err
			}
			if err := producer.WriteChunk(mockModuleName, "message", []byte{0xf4}); err != nil {
				return false, false, err
			}
			return false, true, nil
		},
	}

	fdotest.RunClientTestSuite(t, nil, map[string]serviceinfo.DeviceModule{
		mockModuleName: deviceModule,
	}, func(yield func(string, serviceinfo.OwnerModule) bool) {
		yield(mockModuleName, ownerModule)
	})

	if !deviceModule.ActiveState {
		t.Error("device module should be active")
	}
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
	}, func(yield func(string, serviceinfo.OwnerModule) bool) {
		yield(mockModuleName, struct {
			plugin.Module
			serviceinfo.OwnerModule
		}{
			Module:      ownerPlugin,
			OwnerModule: &fdotest.MockOwnerModule{},
		})
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
