// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo_test

import (
	"context"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/fdotest"
	"github.com/fido-device-onboard/go-fdo/plugin"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

const mockModuleName = "fdotest.mock"

func TestClient(t *testing.T) {
	fdotest.RunClientTestSuite(t, nil, nil, nil, nil)
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
	}, nil)

	if !deviceModule.ActiveState {
		t.Error("device module should be active")
	}
}

func TestClientWithCustomDevmod(t *testing.T) {
	t.Run("Incomplete devmod", func(t *testing.T) {
		customDevmod := &fdotest.MockDeviceModule{
			ReceiveFunc: func(ctx context.Context, moduleName, messageName string, messageBody io.Reader, respond func(message string) io.Writer, yield func()) error {
				_, _ = io.Copy(io.Discard, messageBody)
				return nil
			},
			YieldFunc: func(ctx context.Context, respond func(message string) io.Writer, yield func()) error {
				if err := cbor.NewEncoder(respond("os")).Encode(runtime.GOOS); err != nil {
					return err
				}
				if err := cbor.NewEncoder(respond("arch")).Encode(runtime.GOARCH); err != nil {
					return err
				}
				if err := cbor.NewEncoder(respond("version")).Encode("Debian Bookworm"); err != nil {
					return err
				}
				if err := cbor.NewEncoder(respond("device")).Encode("go-validation"); err != nil {
					return err
				}
				if err := cbor.NewEncoder(respond("sep")).Encode(";"); err != nil {
					return err
				}
				// Leave out bin
				//
				// if err := cbor.NewEncoder(respond("bin")).Encode(runtime.GOARCH); err != nil {
				// 	return err
				// }
				return nil
			},
		}

		fdotest.RunClientTestSuite(t, nil, map[string]serviceinfo.DeviceModule{
			"devmod": customDevmod,
		}, func(yield func(string, serviceinfo.OwnerModule) bool) {}, func(t *testing.T, err error) {
			if err == nil || !strings.Contains(err.Error(), "missing required devmod field: bin") {
				t.Fatalf("expected invalid devmod error, got: %v", err)
			}
		})
	})

	t.Run("Valid devmod", func(t *testing.T) {
		customDevmod := &fdotest.MockDeviceModule{
			ReceiveFunc: func(ctx context.Context, moduleName, messageName string, messageBody io.Reader, respond func(message string) io.Writer, yield func()) error {
				_, _ = io.Copy(io.Discard, messageBody)
				return nil
			},
			YieldFunc: func(ctx context.Context, respond func(message string) io.Writer, yield func()) error {
				if err := cbor.NewEncoder(respond("os")).Encode(runtime.GOOS); err != nil {
					return err
				}
				if err := cbor.NewEncoder(respond("arch")).Encode(runtime.GOARCH); err != nil {
					return err
				}
				if err := cbor.NewEncoder(respond("version")).Encode("Debian Bookworm"); err != nil {
					return err
				}
				if err := cbor.NewEncoder(respond("device")).Encode("go-validation"); err != nil {
					return err
				}
				if err := cbor.NewEncoder(respond("sep")).Encode(";"); err != nil {
					return err
				}
				if err := cbor.NewEncoder(respond("bin")).Encode(runtime.GOARCH); err != nil {
					return err
				}
				return nil
			},
		}

		fdotest.RunClientTestSuite(t, nil, map[string]serviceinfo.DeviceModule{
			"devmod": customDevmod,
		}, func(yield func(string, serviceinfo.OwnerModule) bool) {}, nil)
	})
}

func TestClientWithPluginModule(t *testing.T) {
	devicePlugin, ownerPlugin := fdotest.NewMockPlugin(), fdotest.NewMockPlugin()

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
	}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	select {
	case <-ctx.Done():
		t.Fatal("expected device plugin to be gracefully stopped")
	case <-devicePlugin.GracefulStopped:

	}
	select {
	case <-ctx.Done():
		t.Error("expected device plugin to be forcefully stopped")
	case <-devicePlugin.Stopped:
	}

	select {
	case <-ctx.Done():
		t.Fatal("expected owner plugin to be gracefully stopped")
	case <-ownerPlugin.GracefulStopped:

	}
	select {
	case <-ctx.Done():
		t.Error("expected owner plugin to be forcefully stopped")
	case <-ownerPlugin.Stopped:
	}
}

func TestServerState(t *testing.T) {
	fdotest.RunServerStateSuite(t, nil)
}
