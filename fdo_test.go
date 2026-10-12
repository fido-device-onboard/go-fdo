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

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/custom"
	"github.com/fido-device-onboard/go-fdo/fdotest"
	"github.com/fido-device-onboard/go-fdo/kex"
	"github.com/fido-device-onboard/go-fdo/plugin"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

const mockModuleName = "fdotest.mock"

func TestClient(t *testing.T) {
	fdotest.RunClientTestSuite(t, fdotest.Config{})
}

func TestClientV200(t *testing.T) {
	fdotest.RunClientTestSuite(t, fdotest.Config{
		Version: protocol.Version200,
	})
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

	fdotest.RunClientTestSuite(t, fdotest.Config{
		DeviceModules: map[string]serviceinfo.DeviceModule{
			mockModuleName: deviceModule,
		},
		OwnerModules: func(ctx context.Context, replacementGUID protocol.GUID, info string, chain []*x509.Certificate, devmod serviceinfo.Devmod, supportedMods []string) iter.Seq2[string, serviceinfo.OwnerModule] {
			return func(yield func(string, serviceinfo.OwnerModule) bool) {
				yield(mockModuleName, ownerModule)
			}
		},
	})

	if !deviceModule.ActiveState {
		t.Error("device module should be active")
	}
}

func TestClientWithMockModuleFDO20(t *testing.T) {
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

	fdotest.RunClientTestSuite(t, fdotest.Config{
		Version: protocol.Version200,
		DeviceModules: map[string]serviceinfo.DeviceModule{
			mockModuleName: deviceModule,
		},
		OwnerModules: func(ctx context.Context, replacementGUID protocol.GUID, info string, chain []*x509.Certificate, devmod serviceinfo.Devmod, supportedMods []string) iter.Seq2[string, serviceinfo.OwnerModule] {
			return func(yield func(string, serviceinfo.OwnerModule) bool) {
				yield(mockModuleName, ownerModule)
			}
		},
	})

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

	fdotest.RunClientTestSuite(t, fdotest.Config{
		DeviceModules: map[string]serviceinfo.DeviceModule{
			mockModuleName: deviceModule,
		},
		OwnerModules: func(ctx context.Context, replacementGUID protocol.GUID, info string, chain []*x509.Certificate, devmod serviceinfo.Devmod, supportedMods []string) iter.Seq2[string, serviceinfo.OwnerModule] {
			return func(yield func(string, serviceinfo.OwnerModule) bool) {
				// Provide the owner module twice, because just once will not
				// error due to IsDone=true on the last service info. In this
				// case, the device does not send an error and just discards
				// all remaining service info.
				if !yield(mockModuleName, ownerModule) {
					return
				}
				yield(mockModuleName, ownerModule)
			}
		},
		CustomExpect: func(t *testing.T, err error) {
			if err == nil {
				t.Error("expected err to occur when not handling all message chunks")
			} else if !strings.Contains(err.Error(), "device module did not read full body") {
				t.Error("expected err to refer to device module not reading full message body")
			}
		},
	})

	if !deviceModule.ActiveState {
		t.Error("device module should be active")
	}
}

// The FDO 2.0 client shares the 1.0.1 service info exchange loop, so it also
// detects a device module that does not read a full (auto-unchunked) body.
func TestClientWithMockModuleAndAutoUnchunkingFDO20(t *testing.T) {
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

	fdotest.RunClientTestSuite(t, fdotest.Config{
		Version: protocol.Version200,
		DeviceModules: map[string]serviceinfo.DeviceModule{
			mockModuleName: deviceModule,
		},
		OwnerModules: func(ctx context.Context, replacementGUID protocol.GUID, info string, chain []*x509.Certificate, devmod serviceinfo.Devmod, supportedMods []string) iter.Seq2[string, serviceinfo.OwnerModule] {
			return func(yield func(string, serviceinfo.OwnerModule) bool) {
				if !yield(mockModuleName, ownerModule) {
					return
				}
				yield(mockModuleName, ownerModule)
			}
		},
		CustomExpect: func(t *testing.T, err error) {
			if err == nil {
				t.Error("expected err to occur when not handling all message chunks")
			} else if !strings.Contains(err.Error(), "device module did not read full body") {
				t.Errorf("expected err to refer to device module not reading full message body, got %v", err)
			}
		},
	})

	if !deviceModule.ActiveState {
		t.Error("device module should be active")
	}
}

// sizeCheckingTransport records the largest encoded TO2.DeviceServiceInfo /
// TO2.DeviceSvcInfo20 and collects the chunks of one service info key.
type sizeCheckingTransport struct {
	fdo.Transport
	key     string
	mu      sync.Mutex
	maxSize int
	count   int
	chunks  []byte
}

func (s *sizeCheckingTransport) Send(ctx context.Context, msgType uint8, msg any, sess kex.Session) (uint8, io.ReadCloser, error) {
	if msgType == protocol.TO2DeviceSvcInfo20MsgType || msgType == protocol.TO2DeviceServiceInfoMsgType {
		b, err := cbor.Marshal(msg)
		if err != nil {
			return 0, nil, err
		}
		var info struct {
			ServiceInfo []*serviceinfo.KV
		}
		switch m := msg.(type) {
		case fdo.DeviceSvcInfo20Msg:
			info.ServiceInfo = m.ServiceInfo
		default:
			// FDO 1.01 deviceServiceInfo is unexported: [IsMore, ServiceInfo]
			var v struct {
				IsMore      bool
				ServiceInfo []*serviceinfo.KV
			}
			if err := cbor.Unmarshal(b, &v); err != nil {
				return 0, nil, err
			}
			info.ServiceInfo = v.ServiceInfo
		}
		s.mu.Lock()
		s.count++
		s.maxSize = max(s.maxSize, len(b))
		for _, kv := range info.ServiceInfo {
			if kv.Key == s.key {
				s.chunks = append(s.chunks, kv.Val...)
			}
		}
		s.mu.Unlock()
	}
	return s.Transport.Send(ctx, msgType, msg, sess)
}

// The FDO 2.0 client must honor TO2.SetupDevice20.MaxDeviceServiceInfoSz:
// a large device module response is split across TO2.DeviceSvcInfo20
// messages that each fit, and is reassembled intact by the owner module.
func TestClientFDO20HonorsMaxDeviceServiceInfoSize(t *testing.T) {
	for _, v := range []protocol.Version{protocol.Version101, protocol.Version200} {
		t.Run(v.String(), func(t *testing.T) { testHonorsMaxDeviceServiceInfoSize(t, v) })
	}
}

func testHonorsMaxDeviceServiceInfoSize(t *testing.T, version protocol.Version) {
	const mtu = 600
	big := make([]byte, 5000)
	for i := range big {
		big[i] = byte(i)
	}

	deviceModule := &fdotest.MockDeviceModule{
		ReceiveFunc: func(ctx context.Context, messageName string, messageBody io.Reader, respond func(message string) io.Writer, yield func()) error {
			if _, err := io.Copy(io.Discard, messageBody); err != nil {
				return err
			}
			return cbor.NewEncoder(respond("big")).Encode(big)
		},
	}
	// A single item this large exceeds the per-message budget, so the device
	// splits it into same-key KVs across messages. The spec requires every
	// ServiceInfo item to fit in one message, and the owner side unchunks each
	// message separately, so it cannot reassemble the value: the owner module
	// only drains, and the device side is checked on the wire.
	var received [][]byte
	var requested bool
	var mu sync.Mutex
	ownerModule := &fdotest.MockOwnerModule{
		HandleInfoFunc: func(ctx context.Context, messageName string, messageBody io.Reader) error {
			b, err := io.ReadAll(messageBody)
			if err == nil && messageName == "big" {
				mu.Lock()
				received = append(received, b)
				mu.Unlock()
			}
			return err
		},
		ProduceInfoFunc: func(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
			mu.Lock()
			defer mu.Unlock()
			if len(received) > 0 {
				return false, true, nil
			}
			if requested {
				return false, false, nil // wait for the device's response
			}
			requested = true
			if err := producer.WriteChunk("active", []byte{0xf5}); err != nil {
				return false, false, err
			}
			return false, false, producer.WriteChunk("send", []byte{0xf5})
		},
	}

	var checker *sizeCheckingTransport
	fdotest.RunClientTestSuite(t, fdotest.Config{
		Version: version,
		DeviceModules: map[string]serviceinfo.DeviceModule{
			mockModuleName: deviceModule,
		},
		OwnerModules: func(ctx context.Context, replacementGUID protocol.GUID, info string, chain []*x509.Certificate, devmod serviceinfo.Devmod, supportedMods []string) iter.Seq2[string, serviceinfo.OwnerModule] {
			return func(yield func(string, serviceinfo.OwnerModule) bool) {
				mu.Lock()
				received, requested = nil, false
				mu.Unlock()
				checker.mu.Lock()
				checker.chunks = nil
				checker.mu.Unlock()
				yield(mockModuleName, ownerModule)
			}
		},
		NewTransport: func(t *testing.T, tokens protocol.TokenService, di, to0, to1, to2 protocol.Responder) fdo.Transport {
			to2Server := to2.(*fdo.TO2Server)
			to2Server.MaxDeviceServiceInfoSize = func(context.Context, fdo.Voucher) (uint16, error) { return mtu, nil }
			checker = &sizeCheckingTransport{key: mockModuleName + ":big", Transport: &fdotest.Transport{
				T:            t,
				Tokens:       tokens,
				DIResponder:  di.(*fdo.DIServer[custom.DeviceMfgInfo]),
				TO0Responder: to0.(*fdo.TO0Server),
				TO1Responder: to1.(*fdo.TO1Server),
				TO2Responder: to2Server,
			}}
			return checker
		},
	})

	if checker == nil || checker.count == 0 {
		t.Fatal("no TO2.DeviceSvcInfo20 messages observed")
	}
	if checker.maxSize > mtu {
		t.Errorf("largest TO2.DeviceSvcInfo20 was %d bytes, exceeding MaxDeviceServiceInfoSz %d", checker.maxSize, mtu)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(received) == 0 {
		t.Fatal("owner module received no device response")
	}
	// The last suite run's chunks: the device response, split to fit, must
	// reassemble to the full value
	var got []byte
	if err := cbor.Unmarshal(checker.chunks, &got); err != nil {
		t.Fatalf("device response chunks do not reassemble: %v", err)
	}
	if !slices.Equal(got, big) {
		t.Fatalf("device sent %d bytes, want the %d byte response intact", len(got), len(big))
	}
	t.Logf("%d device service info messages, largest %d bytes (limit %d)", checker.count, checker.maxSize, mtu)
}

func TestClientWithCustomDevmodFDO20(t *testing.T) {
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
				return nil
			},
		}

		fdotest.RunClientTestSuite(t, fdotest.Config{
			Version: protocol.Version200,
			DeviceModules: map[string]serviceinfo.DeviceModule{
				"devmod": customDevmod,
			},
			CustomExpect: func(t *testing.T, err error) {
				if err == nil || !strings.Contains(err.Error(), "missing required devmod field: bin") {
					t.Fatalf("expected invalid devmod error, got: %v", err)
				}
			},
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

		fdotest.RunClientTestSuite(t, fdotest.Config{
			Version: protocol.Version200,
			DeviceModules: map[string]serviceinfo.DeviceModule{
				"devmod": customDevmod,
			},
		})
	})
}

func TestClientWithPluginModuleFDO20(t *testing.T) {
	devicePlugin := new(fdotest.MockPlugin)
	devicePlugin.Routines = fdotest.ModuleNameOnlyRoutines(mockModuleName)
	ownerPlugins := make(chan *fdotest.MockPlugin, 1000)

	fdotest.RunClientTestSuite(t, fdotest.Config{
		Version: protocol.Version200,
		DeviceModules: map[string]serviceinfo.DeviceModule{
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
		},
		OwnerModules: func(ctx context.Context, replacementGUID protocol.GUID, info string, chain []*x509.Certificate, devmod serviceinfo.Devmod, supportedMods []string) iter.Seq2[string, serviceinfo.OwnerModule] {
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
		},
	})
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

		fdotest.RunClientTestSuite(t, fdotest.Config{
			DeviceModules: map[string]serviceinfo.DeviceModule{
				"devmod": customDevmod,
			},
			CustomExpect: func(t *testing.T, err error) {
				if err == nil || !strings.Contains(err.Error(), "missing required devmod field: bin") {
					t.Fatalf("expected invalid devmod error, got: %v", err)
				}
			},
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

		fdotest.RunClientTestSuite(t, fdotest.Config{
			DeviceModules: map[string]serviceinfo.DeviceModule{
				"devmod": customDevmod,
			},
		})
	})
}

func TestClientWithPluginModule(t *testing.T) {
	devicePlugin := new(fdotest.MockPlugin)
	devicePlugin.Routines = fdotest.ModuleNameOnlyRoutines(mockModuleName)
	ownerPlugins := make(chan *fdotest.MockPlugin, 1000)

	fdotest.RunClientTestSuite(t, fdotest.Config{
		DeviceModules: map[string]serviceinfo.DeviceModule{
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
		},
		OwnerModules: func(ctx context.Context, replacementGUID protocol.GUID, info string, chain []*x509.Certificate, devmod serviceinfo.Devmod, supportedMods []string) iter.Seq2[string, serviceinfo.OwnerModule] {
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
		},
	})
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
