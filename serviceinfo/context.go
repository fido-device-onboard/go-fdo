// SPDX-FileCopyrightText: (C) 2025 Ben Krieger
// SPDX-License-Identifier: Apache 2.0

package serviceinfo

import (
	"context"
	"crypto/x509"

	"github.com/fido-device-onboard/go-fdo/protocol"
)

type (
	devmodKey           struct{}
	supportedModulesKey struct{}
	deviceCertKey       struct{}
	guidKey             struct{}
	replacementGUIDKey  struct{}
)

// Context creates a context with the values expected by native FSIM
// implementations.
func Context(parent context.Context, devmod *Devmod, supportedModules []string, deviceCertChain []*x509.Certificate, guid, replacement protocol.GUID) context.Context {
	return context.WithValue(context.WithValue(context.WithValue(context.WithValue(context.WithValue(parent,
		devmodKey{}, devmod),
		supportedModulesKey{}, supportedModules),
		deviceCertKey{}, deviceCertChain),
		guidKey{}, guid),
		replacementGUIDKey{}, replacement)
}

// DevmodFromContext returns the devmod for the current session. The ctx must
// be from the first argument of HandleInfo or ProduceInfo for an OwnerModule.
func DevmodFromContext(ctx context.Context) (devmod *Devmod, ok bool) {
	devmod, ok = ctx.Value(devmodKey{}).(*Devmod)
	return
}

// DeviceSupportedModulesFromContext returns the supported modules for the
// current session. The ctx must be from the first argument of HandleInfo or
// ProduceInfo for an OwnerModule.
func DeviceSupportedModulesFromContext(ctx context.Context) (supported []string, ok bool) {
	supported, ok = ctx.Value(supportedModulesKey{}).([]string)
	return
}

// DeviceCertificateFromContext returns the device certificate chain for the
// current session. The ctx must be from the first argument of HandleInfo or
// ProduceInfo for an OwnerModule.
func DeviceCertificateFromContext(ctx context.Context) (devCert []*x509.Certificate, ok bool) {
	devCert, ok = ctx.Value(deviceCertKey{}).([]*x509.Certificate)
	return
}

// GUIDFromContext returns the device GUID for the current session. The ctx
// must be from the first argument of HandleInfo or ProduceInfo for an
// OwnerModule.
func GUIDFromContext(ctx context.Context) (guid protocol.GUID, ok bool) {
	guid, ok = ctx.Value(guidKey{}).(protocol.GUID)
	return
}

// ReplacementGUIDFromContext returns the GUID the device will have if TO2
// succeeds. The ctx must be from the first argument of HandleInfo or
// ProduceInfo for an OwnerModule.
func ReplacementGUIDFromContext(ctx context.Context) (replacement protocol.GUID, ok bool) {
	replacement, ok = ctx.Value(guidKey{}).(protocol.GUID)
	return
}
