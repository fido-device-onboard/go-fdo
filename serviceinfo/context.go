// SPDX-FileCopyrightText: (C) 2025 Ben Krieger
// SPDX-License-Identifier: Apache 2.0

package serviceinfo

import (
	"context"
	"crypto/x509"
)

type (
	devmodKey struct{}
	devcrtKey struct{}
)

// Context creates a context with the values expected by native FSIM
// implementations.
func Context(parent context.Context, devmod *Devmod, devCert []*x509.Certificate) context.Context {
	return context.WithValue(context.WithValue(parent,
		devmodKey{}, devmod),
		devcrtKey{}, devCert)
}

// DevmodFromContext returns the devmod for the current session. The ctx must
// be from the first argument of HandleInfo or ProduceInfo for an OwnerModule.
func DevmodFromContext(ctx context.Context) (devmod *Devmod, ok bool) {
	devmod, ok = ctx.Value(devmodKey{}).(*Devmod)
	return
}

// DeviceCertificateFromContext returns the device certificate chain for the
// current session. The ctx must be from the first argument of HandleInfo or
// ProduceInfo for an OwnerModule.
func DeviceCertificateFromContext(ctx context.Context) (devCert []*x509.Certificate, ok bool) {
	devCert, ok = ctx.Value(devcrtKey{}).([]*x509.Certificate)
	return
}
