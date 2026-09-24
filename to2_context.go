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

	// ctxKeyDelegateProvision is true when the TO2 peer authenticated as
	// a delegate whose certificate chain carries OIDPermitProvision
	// (PERM.7). FSIMs check this to decide whether unsigned provisioning
	// messages are acceptable (Model 2: delegate channel authority).
	ctxKeyDelegateProvision
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

// WithDelegateProvisionAuthority returns a context recording that the TO2
// peer proved it holds a delegate certificate with OIDPermitProvision
// (PERM.7). The BMO device module reads this to allow unsigned
// provisioning messages under Model 2 (delegate channel authority).
func WithDelegateProvisionAuthority(ctx context.Context, hasProvision bool) context.Context {
	if !hasProvision {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyDelegateProvision, true)
}

// DelegateProvisionAuthorityFromContext returns true if the TO2 peer proved
// delegate provisioning authority (PERM.7), as set by
// WithDelegateProvisionAuthority.
func DelegateProvisionAuthorityFromContext(ctx context.Context) bool {
	if v, ok := ctx.Value(ctxKeyDelegateProvision).(bool); ok {
		return v
	}
	return false
}
