// SPDX-FileCopyrightText: (C) 2025 Ben Krieger
// SPDX-License-Identifier: Apache 2.0

package serviceinfo_test

import (
	"context"
	"crypto/x509"
	"iter"
	"reflect"
	"testing"

	"github.com/fido-device-onboard/go-fdo/fdotest"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

const mockModuleName = "fdotest.mock"

func TestOwnerModuleContextValues(t *testing.T) {
	var (
		expectedDevmod        *serviceinfo.Devmod
		expectedSupportedMods []string
		expectedCertChain     []*x509.Certificate
	)

	deviceModule := &fdotest.MockDeviceModule{}
	ownerModule := &fdotest.MockOwnerModule{
		ProduceInfoFunc: func(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
			if gotDevmod, ok := serviceinfo.DevmodFromContext(ctx); !ok {
				t.Error("devmod from context is empty")
			} else if !reflect.DeepEqual(expectedDevmod, gotDevmod) {
				t.Errorf("expected devmod %+v, got %+v", *expectedDevmod, *gotDevmod)
			}

			if gotSupportedMods, ok := serviceinfo.DeviceSupportedModulesFromContext(ctx); !ok {
				t.Error("device supported mods from context is empty")
			} else if !reflect.DeepEqual(expectedSupportedMods, gotSupportedMods) {
				t.Errorf("expected device supported mods %+v, got %+v", expectedSupportedMods, gotSupportedMods)
			}

			if gotCertChain, ok := serviceinfo.DeviceCertificateFromContext(ctx); !ok {
				t.Error("device certificate chain from context is empty")
			} else if !reflect.DeepEqual(expectedCertChain, gotCertChain) {
				t.Errorf("expected device certificate chain %+v, got %+v", expectedCertChain, gotCertChain)
			}

			return false, true, nil
		},
	}

	fdotest.RunClientTestSuite(t, fdotest.Config{
		DeviceModules: map[string]serviceinfo.DeviceModule{
			mockModuleName: deviceModule,
		},
		OwnerModules: func(ctx context.Context, replacementGUID protocol.GUID, info string, chain []*x509.Certificate, devmod serviceinfo.Devmod, supportedMods []string) iter.Seq2[string, serviceinfo.OwnerModule] {
			expectedDevmod = &devmod
			expectedSupportedMods = supportedMods
			expectedCertChain = chain
			return func(yield func(string, serviceinfo.OwnerModule) bool) { yield(mockModuleName, ownerModule) }
		},
	})
}
