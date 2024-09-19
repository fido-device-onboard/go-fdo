// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo_test

import (
	"context"
	"crypto/x509"
	"io"
	"iter"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/fdotest"
	"github.com/fido-device-onboard/go-fdo/plugin"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

const mockModuleName = "fdotest.mock"

func TestClient(t *testing.T) {
	fdotest.RunClientTestSuite(t, nil, nil, nil, nil)
}

func TestClientWithMockModule(t *testing.T) {
	deviceModule := &fdotest.MockDeviceModule{
		ReceiveFunc: func(ctx context.Context, messageName string, messageBody io.Reader, respond func(message string) io.Writer, yield func()) error {
			_, _ = io.Copy(io.Discard, messageBody)
			return nil
		},
	}
	ownerModule := &fdotest.MockOwnerModule{
		ProduceInfoFunc: func(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
			if err := producer.WriteChunk("active", []byte{0xf5}); err != nil {
				return false, false, err
			}
			if err := producer.WriteChunk("message", []byte{0xf4}); err != nil {
				return false, false, err
			}
			return false, true, nil
		},
	}

	fdotest.RunClientTestSuite(t, nil, map[string]serviceinfo.DeviceModule{
		mockModuleName: deviceModule,
	}, func(ctx context.Context, replacementGUID protocol.GUID, info string, chain []*x509.Certificate, devmod serviceinfo.Devmod, supportedMods []string) iter.Seq2[string, serviceinfo.OwnerModule] {
		return func(yield func(string, serviceinfo.OwnerModule) bool) {
			yield(mockModuleName, ownerModule)
		}
	}, nil)

	if !deviceModule.ActiveState {
		t.Error("device module should be active")
	}
}

func TestClientWithMockModuleAndAutoUnchunking(t *testing.T) {
	deviceModule := &fdotest.MockDeviceModule{
		ReceiveFunc: func(ctx context.Context, messageName string, messageBody io.Reader, respond func(message string) io.Writer, yield func()) error {
			var v any
			return cbor.NewDecoder(messageBody).Decode(&v)
		},
	}
	ownerModule := &fdotest.MockOwnerModule{
		ProduceInfoFunc: func(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
			if err := producer.WriteChunk("active", []byte{0xf5}); err != nil {
				return false, false, err
			}
			if err := producer.WriteChunk("message", []byte{0xf4}); err != nil {
				return false, false, err
			}
			if err := producer.WriteChunk("message", []byte{0xf4}); err != nil {
				return false, false, err
			}
			return false, true, nil
		},
	}

	fdotest.RunClientTestSuite(t, nil, map[string]serviceinfo.DeviceModule{
		mockModuleName: deviceModule,
	}, func(ctx context.Context, replacementGUID protocol.GUID, info string, chain []*x509.Certificate, devmod serviceinfo.Devmod, supportedMods []string) iter.Seq2[string, serviceinfo.OwnerModule] {
		return func(yield func(string, serviceinfo.OwnerModule) bool) {
			yield(mockModuleName, ownerModule)
		}
	}, func(t *testing.T, err error) {
		if err == nil {
			t.Error("expected err to occur when not handling all message chunks")
		}
		if !strings.Contains(err.Error(), "device module did not read full body") {
			t.Error("expected err to refer to device module not reading full message body")
		}
	})

	if !deviceModule.ActiveState {
		t.Error("device module should be active")
	}
}

func TestClientWithCustomDevmod(t *testing.T) {
	t.Run("Incomplete devmod", func(t *testing.T) {
		customDevmod := &fdotest.MockDeviceModule{
			ReceiveFunc: func(ctx context.Context, messageName string, messageBody io.Reader, respond func(message string) io.Writer, yield func()) error {
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
		}, nil, func(t *testing.T, err error) {
			if err == nil || !strings.Contains(err.Error(), "missing required devmod field: bin") {
				t.Fatalf("expected invalid devmod error, got: %v", err)
			}
		})
	})

	t.Run("Valid devmod", func(t *testing.T) {
		customDevmod := &fdotest.MockDeviceModule{
			ReceiveFunc: func(ctx context.Context, messageName string, messageBody io.Reader, respond func(message string) io.Writer, yield func()) error {
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
		}, nil, nil)
	})
}

func TestClientWithPluginModule(t *testing.T) {
	devicePlugin := new(fdotest.MockPlugin)
	devicePlugin.Routines = fdotest.ModuleNameOnlyRoutines(mockModuleName)
	ownerPlugins := make(chan *fdotest.MockPlugin, 1000)

	fdotest.RunClientTestSuite(t, nil, map[string]serviceinfo.DeviceModule{
		mockModuleName: struct {
			plugin.Module
			serviceinfo.DeviceModule
		}{
			Module: devicePlugin,
			DeviceModule: &fdotest.MockDeviceModule{
				TransitionFunc: func(active bool) error {
					if active {
						_, _, err := devicePlugin.Start()
						return err
					}
					return nil
				},
			},
		},
	}, func(ctx context.Context, replacementGUID protocol.GUID, info string, chain []*x509.Certificate, devmod serviceinfo.Devmod, supportedMods []string) iter.Seq2[string, serviceinfo.OwnerModule] {
		return func(yield func(string, serviceinfo.OwnerModule) bool) {
			var once sync.Once
			ownerPlugin := new(fdotest.MockPlugin)
			ownerPlugin.Routines = fdotest.ModuleNameOnlyRoutines(mockModuleName)
			if !yield(mockModuleName, struct {
				plugin.Module
				serviceinfo.OwnerModule
			}{
				Module: ownerPlugin,
				OwnerModule: &fdotest.MockOwnerModule{
					ProduceInfoFunc: func(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, err error) {
						once.Do(func() { _, _, err = ownerPlugin.Start() })
						if err != nil {
							return false, false, err
						}
						return false, true, producer.WriteChunk("active", []byte{0xf5})
					},
				},
			}) {
				return
			}
			if slices.Contains(supportedMods, mockModuleName) {
				ownerPlugins <- ownerPlugin
			}
		}
	}, nil)
	close(ownerPlugins)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
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

	for ownerPlugin := range ownerPlugins {
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
}

func TestServerState(t *testing.T) {
	fdotest.RunServerStateSuite(t, nil)
}
