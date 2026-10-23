// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"log/slog"
	"strings"
	"time"

	fdo "github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/fsim/chunking"
)

// authorizeGated authorizes one authorization-gated message
// (chunking-strategy.md "Authorization of Begin Messages") and returns its
// inner payload. It is shared by every FSIM that declares gated messages
// (fdo.bmo image-begin/set, fdo.payload payload-begin), so there is one
// implementation of the decision.
//
//   - Tagged COSE_Sign1: artifact authority. Verified with the FSIM's
//     content type and external AAD, Owner key or PERM.7 x5chain, scope
//     evaluated fail-closed. No downgrade on failure.
//   - Bare payload: channel authority, decided from the TO2 peer authority.
//     If refused, allowUnauthorized (optional) may grant a documented local
//     exception for that specific payload; it is never consulted for a
//     signed message.
func authorizeGated(ctx context.Context, raw []byte, ownerKey crypto.PublicKey, contentType string, aad []byte,
	allowUnauthorized func(inner []byte) (bool, string)) (inner []byte, signed bool, err error) {
	if chunking.IsSigned(raw) {
		payload, err := chunking.VerifyArtifact(raw, ownerKey, contentType, aad, chunking.ScopeContext{
			DeviceGUID: fdo.DeviceGUIDFromContext(ctx),
			Now:        time.Now,
		})
		if err != nil {
			return nil, true, err
		}
		return payload, true, nil
	}

	// Unsigned — channel authority. Decided from who the TO2 peer proved
	// itself to be, never from whether an Owner key happens to be known.
	ok, reason := unsignedProvisioningAllowed(fdo.PeerAuthorityFromContext(ctx), ownerKey != nil)
	if !ok && allowUnauthorized != nil {
		if allowed, why := allowUnauthorized(raw); allowed {
			slog.Warn("accepting unsigned message from a peer WITHOUT provisioning authority under a documented local policy",
				"content_type", contentType, "policy", why)
			return raw, false, nil
		}
	}
	if !ok {
		return nil, false, &chunking.TransferError{Code: chunking.CodeNotAuthorized,
			Msg: fmt.Sprintf("unsigned %s rejected: %s (see chunking-strategy.md §Channel Authority)", contentType, reason)}
	}
	slog.Info("accepting unsigned message via channel authority", "content_type", contentType, "reason", reason)
	return raw, false, nil
}

// unsignedProvisioningAllowed decides whether an unsigned provisioning
// message is acceptable under channel authority:
//
//   - Owner-direct peer (Model 1): accepted.
//   - Delegate with PERM.7 (Model 2): accepted.
//   - Delegate without PERM.7: rejected; it may only relay signed artifacts.
//   - No recorded peer: rejected if an Owner key is known (inconsistent
//     state, fail closed); accepted only in legacy/test setups with no
//     Owner key at all.
func unsignedProvisioningAllowed(peer fdo.PeerAuthority, ownerKeyKnown bool) (bool, string) {
	switch peer {
	case fdo.PeerOwnerDirect:
		return true, "Owner channel authority (Model 1)"
	case fdo.PeerDelegateProvision:
		return true, "delegate channel authority with PERM.7 (Model 2)"
	case fdo.PeerDelegateOnboardOnly:
		return false, "TO2 peer is a delegate without provisioning permission (PERM.7); it may only relay signed artifacts"
	default:
		if ownerKeyKnown {
			return false, "Owner key is known but no TO2 peer authority was recorded"
		}
		return true, "legacy/test mode: no Owner key"
	}
}

// checkSignedBeginBindsContent enforces that a signed inline image-begin
// carries expected_hash (key 8): image-end is never signed, so without it the
// signature authorises only metadata, not the image (chunking-strategy.md
// "Hash Handling"). Fetched content (modes 1/2) is governed by
// chunking.Resolve instead.
func checkSignedBeginBindsContent(inner []byte, signed bool) error {
	var begin chunking.BeginMessage
	if err := begin.UnmarshalCBOR(inner); err != nil {
		return fmt.Errorf("malformed image-begin: %w", err)
	}
	if signed && begin.DeliveryMode == DeliveryModeInline && len(begin.ExpectedHash) == 0 {
		return fmt.Errorf("signed inline image-begin has no expected_hash (key 8); the signature would not cover the image")
	}
	return nil
}

// verifyBeginHash checks inline content against expected_hash (key 8) in the
// authorizing *-begin, if present.
func verifyBeginHash(data []byte, begin chunking.BeginMessage) error {
	if len(begin.ExpectedHash) == 0 {
		return nil
	}
	alg := strings.ToLower(begin.HashAlg)
	if alg == "" {
		alg = "sha256"
	}
	if err := chunking.VerifyHash(alg, data, begin.ExpectedHash); err != nil {
		return &chunking.TransferError{Code: chunking.CodeHashMismatch, Msg: fmt.Sprintf("content does not match expected_hash (key 8): %v", err)}
	}
	return nil
}

// newBeginHasher returns a running hash for expected_hash in streaming mode.
func newBeginHasher(hashAlg string) (hash.Hash, error) {
	switch strings.ToLower(hashAlg) {
	case "", "sha256":
		return sha256.New(), nil
	case "sha384":
		return sha512.New384(), nil
	case "sha512":
		return sha512.New(), nil
	}
	return nil, &chunking.TransferError{Code: chunking.CodeNotAuthorized, Msg: "unsupported hash algorithm " + hashAlg}
}
