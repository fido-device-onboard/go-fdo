// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"crypto"

	"github.com/fido-device-onboard/go-fdo/protocol"
)

// ctxKey is an unexported context-key type to avoid collisions.
type ctxKey int

const (
	// ctxKeyOwnerPubKey stores the TO2-proven Owner public key so that
	// device-side serviceinfo modules (FSIMs) can access it for
	// authenticated-provisioning verification (see fdo.bmo.md).
	ctxKeyOwnerPubKey ctxKey = iota

	// ctxKeyPeerAuthority stores the PeerAuthority of the TO2 peer, as
	// determined from how TO2.ProveOVHdr was verified.
	ctxKeyPeerAuthority

	// ctxKeyDeviceGUID stores the GUID from the Ownership Voucher proven in
	// TO2, used to evaluate "guid" scope constraints on signed artifacts.
	ctxKeyDeviceGUID
)

// WithDeviceGUID returns a context carrying the voucher GUID proven in TO2.
// This is the GUID a "guid" scope constraint is compared against — not any
// replacement GUID delivered in TO2.SetupDevice.
func WithDeviceGUID(ctx context.Context, guid protocol.GUID) context.Context {
	g := make([]byte, len(guid))
	copy(g, guid[:])
	return context.WithValue(ctx, ctxKeyDeviceGUID, g)
}

// DeviceGUIDFromContext returns the voucher GUID stored by WithDeviceGUID, or
// nil if none is set.
func DeviceGUIDFromContext(ctx context.Context) []byte {
	if v, ok := ctx.Value(ctxKeyDeviceGUID).([]byte); ok {
		return v
	}
	return nil
}

// PeerAuthority records who the TO2 peer proved itself to be when
// TO2.ProveOVHdr was verified. FSIMs use it to decide whether unsigned
// provisioning messages are acceptable (channel authority).
//
// It must be set explicitly by TO2. It cannot be inferred from the presence
// of an Owner public key: the device knows the Owner key from the voucher
// whether the peer is the Owner or a Delegate, so "Owner key present" would
// treat every onboard-only Delegate as the Owner.
type PeerAuthority int

const (
	// PeerUnknown means no TO2-proven peer was recorded (legacy/test paths).
	PeerUnknown PeerAuthority = iota
	// PeerOwnerDirect means ProveOVHdr verified directly against the Owner
	// key. The peer holds provisioning authority (Model 1).
	PeerOwnerDirect
	// PeerDelegateProvision means ProveOVHdr verified against a Delegate
	// chain rooted in the Owner key that grants OIDPermitProvision (PERM.7).
	// The peer holds provisioning authority (Model 2).
	PeerDelegateProvision
	// PeerDelegateOnboardOnly means ProveOVHdr verified against a Delegate
	// chain that does not grant PERM.7. The peer may relay signed artifacts
	// but MUST NOT be trusted for unsigned provisioning messages.
	PeerDelegateOnboardOnly
)

// HasProvisionAuthority reports whether the peer may supply unsigned
// provisioning messages under channel authority.
func (p PeerAuthority) HasProvisionAuthority() bool {
	return p == PeerOwnerDirect || p == PeerDelegateProvision
}

func (p PeerAuthority) String() string {
	switch p {
	case PeerOwnerDirect:
		return "owner-direct"
	case PeerDelegateProvision:
		return "delegate+provision"
	case PeerDelegateOnboardOnly:
		return "delegate(onboard-only)"
	default:
		return "unknown"
	}
}

// WithPeerAuthority returns a context recording the TO2 peer's authority.
func WithPeerAuthority(ctx context.Context, p PeerAuthority) context.Context {
	return context.WithValue(ctx, ctxKeyPeerAuthority, p)
}

// PeerAuthorityFromContext returns the TO2 peer's authority stored by
// WithPeerAuthority, or PeerUnknown if none is set.
func PeerAuthorityFromContext(ctx context.Context) PeerAuthority {
	if v, ok := ctx.Value(ctxKeyPeerAuthority).(PeerAuthority); ok {
		return v
	}
	return PeerUnknown
}

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

// WithDelegateProvisionAuthority records the TO2 peer as a Delegate, with
// or without PERM.7.
//
// Deprecated: use WithPeerAuthority, which can also express Owner-direct.
func WithDelegateProvisionAuthority(ctx context.Context, hasProvision bool) context.Context {
	if hasProvision {
		return WithPeerAuthority(ctx, PeerDelegateProvision)
	}
	return WithPeerAuthority(ctx, PeerDelegateOnboardOnly)
}

// DelegateProvisionAuthorityFromContext returns true if the TO2 peer is a
// Delegate holding PERM.7.
//
// Deprecated: use PeerAuthorityFromContext.
func DelegateProvisionAuthorityFromContext(ctx context.Context) bool {
	return PeerAuthorityFromContext(ctx) == PeerDelegateProvision
}

// peerAuthorityFromDelegateChain derives the PeerAuthority from the delegate
// chain that accompanied a successfully verified ProveOVHdr. A nil chain
// means ProveOVHdr verified against the Owner key directly. A chain that
// cannot be decoded fails closed to onboard-only.
func peerAuthorityFromDelegateChain(delegateChain *protocol.PublicKey) PeerAuthority {
	if delegateChain == nil {
		return PeerOwnerDirect
	}
	certs, err := delegateChain.Chain()
	if err != nil || !DelegateCanProvision(certs) {
		return PeerDelegateOnboardOnly
	}
	return PeerDelegateProvision
}
