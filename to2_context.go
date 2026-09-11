// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"crypto"
)

// ctxKey is an unexported context-key type to avoid collisions.
type ctxKey int

const (
	// ctxKeyOwnerPubKey stores the TO2-proven Owner public key so that
	// device-side serviceinfo modules (FSIMs) can access it for
	// authenticated-provisioning verification (see fdo.bmo.md).
	ctxKeyOwnerPubKey ctxKey = iota
)

// WithOwnerPublicKey returns a context carrying the TO2-proven Owner public
// key. The TO2 device-side flow calls this before invoking FSIM handlers so
// that modules like fdo.bmo can retrieve the trust anchor for signed
// provisioning messages without explicit plumbing.
func WithOwnerPublicKey(ctx context.Context, key crypto.PublicKey) context.Context {
	if key == nil {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyOwnerPubKey, key)
}

// OwnerPublicKeyFromContext returns the TO2-proven Owner public key stored in
// ctx by WithOwnerPublicKey, or nil if none is set.
func OwnerPublicKeyFromContext(ctx context.Context) crypto.PublicKey {
	if v := ctx.Value(ctxKeyOwnerPubKey); v != nil {
		return v
	}
	return nil
}
