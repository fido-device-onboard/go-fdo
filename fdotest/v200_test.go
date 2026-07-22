// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdotest_test

import (
	"context"
	"io"
	"testing"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/fdotest"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"

	"crypto/x509"
	"iter"
	"strings"
)

// TestTO2v200FullFlow exercises the complete DI -> TO0 -> TO1 -> TO2 flow
// using FDO 2.0 message types (80-91). This is the primary happy-path test
// for FDO 2.0 and validates that all protocol phases interoperate correctly
// with the v2.0 TO2 client (fdo.TO2v200).
func TestTO2v200FullFlow(t *testing.T) {
	fdotest.RunClientTestSuite(t, fdotest.Config{
		ProtocolVersion: protocol.Version200,
	})
}

// TestTO2v200WithCredentialReuse verifies that FDO 2.0 TO2 correctly supports
// the Credential Reuse Protocol (Section 7). In v2.0, the replacement HMAC
// is carried in Done20 (type 90) rather than DeviceSvcInfoRdy as in v1.1.
func TestTO2v200WithCredentialReuse(t *testing.T) {
	fdotest.RunClientTestSuite(t, fdotest.Config{
		ProtocolVersion: protocol.Version200,
		Reuse:           true,
	})
}

const v200MockModuleName = "fdotest.v200mock"

// TestTO2v200WithMockModule verifies that FDO 2.0 service info exchange
// (DeviceSvcInfo20/OwnerSvcInfo20, types 88/89) works correctly with
// device and owner modules. This exercises the encrypted service info
// path that begins at type 86 (DeviceSvcInfoRdy20).
func TestTO2v200WithMockModule(t *testing.T) {
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
			if err := producer.WriteChunk("data", []byte{0xf4}); err != nil {
				return false, false, err
			}
			return false, true, nil
		},
	}

	fdotest.RunClientTestSuite(t, fdotest.Config{
		ProtocolVersion: protocol.Version200,
		DeviceModules: map[string]serviceinfo.DeviceModule{
			v200MockModuleName: deviceModule,
		},
		OwnerModules: func(ctx context.Context, replacementGUID protocol.GUID, info string, chain []*x509.Certificate, devmod serviceinfo.Devmod, supportedMods []string) iter.Seq2[string, serviceinfo.OwnerModule] {
			return func(yield func(string, serviceinfo.OwnerModule) bool) {
				yield(v200MockModuleName, ownerModule)
			}
		},
	})

	if !deviceModule.ActiveState {
		t.Error("device module should be active after FDO 2.0 TO2 with modules")
	}
}

// TestTO2v200WithCredentialReuseAndModules verifies FDO 2.0 credential reuse
// combined with service info modules. This ensures that the Done20 message
// correctly carries a nil ReplacementHmac when credential reuse is in effect
// and service info was exchanged.
func TestTO2v200WithCredentialReuseAndModules(t *testing.T) {
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
			return false, true, nil
		},
	}

	fdotest.RunClientTestSuite(t, fdotest.Config{
		ProtocolVersion: protocol.Version200,
		Reuse:           true,
		DeviceModules: map[string]serviceinfo.DeviceModule{
			v200MockModuleName: deviceModule,
		},
		OwnerModules: func(ctx context.Context, replacementGUID protocol.GUID, info string, chain []*x509.Certificate, devmod serviceinfo.Devmod, supportedMods []string) iter.Seq2[string, serviceinfo.OwnerModule] {
			return func(yield func(string, serviceinfo.OwnerModule) bool) {
				yield(v200MockModuleName, ownerModule)
			}
		},
	})
}

// TestTO2v200DeviceModuleAutoUnchunking verifies that FDO 2.0 service info
// correctly handles the case where a device module does not read the full
// message body, triggering auto-unchunking behavior.
func TestTO2v200DeviceModuleAutoUnchunking(t *testing.T) {
	deviceModule := &fdotest.MockDeviceModule{
		ReceiveFunc: func(ctx context.Context, messageName string, messageBody io.Reader, respond func(message string) io.Writer, yield func()) error {
			// Decode as a single value, requiring auto-unchunking
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
		ProtocolVersion: protocol.Version200,
		DeviceModules: map[string]serviceinfo.DeviceModule{
			v200MockModuleName: deviceModule,
		},
		OwnerModules: func(ctx context.Context, replacementGUID protocol.GUID, info string, chain []*x509.Certificate, devmod serviceinfo.Devmod, supportedMods []string) iter.Seq2[string, serviceinfo.OwnerModule] {
			return func(yield func(string, serviceinfo.OwnerModule) bool) {
				if !yield(v200MockModuleName, ownerModule) {
					return
				}
				yield(v200MockModuleName, ownerModule)
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
}

// TestTO2v200NoDebugLogging verifies FDO 2.0 protocol works with reduced
// (info-level) logging, confirming that debug-level log statements do not
// cause panics or affect protocol behavior.
func TestTO2v200NoDebugLogging(t *testing.T) {
	fdotest.RunClientTestSuite(t, fdotest.Config{
		ProtocolVersion: protocol.Version200,
		NoDebug:         true,
	})
}
