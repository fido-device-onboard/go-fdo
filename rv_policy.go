// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// VoucherReplacementPolicy defines how the RV service handles voucher replacements
// for the same GUID.
type VoucherReplacementPolicy int

const (
	// RVPolicyAllowAny allows any valid voucher to replace an existing GUID registration.
	// This provides maximum operational flexibility but minimal protection against
	// malicious GUID collision attacks. (Option 0)
	RVPolicyAllowAny VoucherReplacementPolicy = iota

	// RVPolicyManufacturerKeyConsistency requires that voucher replacements for the same
	// GUID must be signed by the same manufacturer. This prevents cross-manufacturer
	// GUID collision attacks while allowing legitimate owner key rotation and service
	// address updates. (Option 1 - Recommended)
	RVPolicyManufacturerKeyConsistency

	// RVPolicyFirstRegistrationLock locks the GUID to the first registered voucher
	// until expiration. Only allows replacement after the TTL expires. This provides
	// maximum protection but blocks all corrections during the validity period. (Option 2)
	RVPolicyFirstRegistrationLock

	// RVPolicyOwnerKeyConsistency requires that replacements must be signed by the same
	// owner (final entry in voucher chain). This allows manufacturer key rotation but
	// prevents ownership transfers. (Option 3)
	RVPolicyOwnerKeyConsistency
)

// String returns the string representation of the policy.
func (p VoucherReplacementPolicy) String() string {
	switch p {
	case RVPolicyAllowAny:
		return "allow-any"
	case RVPolicyManufacturerKeyConsistency:
		return "manufacturer-key-consistency"
	case RVPolicyFirstRegistrationLock:
		return "first-registration-lock"
	case RVPolicyOwnerKeyConsistency:
		return "owner-key-consistency"
	default:
		return fmt.Sprintf("unknown(%d)", p)
	}
}

// ParseVoucherReplacementPolicy parses a policy string into a VoucherReplacementPolicy.
func ParseVoucherReplacementPolicy(s string) (VoucherReplacementPolicy, error) {
	switch s {
	case "allow-any", "0":
		return RVPolicyAllowAny, nil
	case "manufacturer-key-consistency", "1":
		return RVPolicyManufacturerKeyConsistency, nil
	case "first-registration-lock", "2":
		return RVPolicyFirstRegistrationLock, nil
	case "owner-key-consistency", "3":
		return RVPolicyOwnerKeyConsistency, nil
	default:
		return RVPolicyAllowAny, fmt.Errorf("invalid voucher replacement policy: %s", s)
	}
}

// CheckVoucherReplacement checks if a voucher replacement is allowed according to the policy.
// Returns an error if the replacement should be rejected.
func CheckVoucherReplacement(
	ctx context.Context,
	policy VoucherReplacementPolicy,
	newVoucher *Voucher,
	existingBlob RendezvousBlobPersistentState,
) error {
	if policy == RVPolicyAllowAny {
		return nil // No restrictions
	}

	guid := newVoucher.Header.Val.GUID

	// Check if GUID already exists
	_, existingVoucher, err := existingBlob.RVBlob(ctx, guid)
	if errors.Is(err, ErrNotFound) {
		return nil // First registration, always allowed
	}
	if err != nil {
		return fmt.Errorf("error checking existing voucher: %w", err)
	}

	switch policy {
	case RVPolicyManufacturerKeyConsistency:
		return checkManufacturerKeyConsistency(newVoucher, existingVoucher)

	case RVPolicyFirstRegistrationLock:
		return checkFirstRegistrationLock(existingVoucher)

	case RVPolicyOwnerKeyConsistency:
		return checkOwnerKeyConsistency(newVoucher, existingVoucher)

	default:
		return fmt.Errorf("unknown voucher replacement policy: %d", policy)
	}
}

// checkManufacturerKeyConsistency verifies that the manufacturer key matches.
func checkManufacturerKeyConsistency(newVoucher, existingVoucher *Voucher) error {
	existingMfgHash, err := hashPublicKey(existingVoucher.Header.Val.ManufacturerKey)
	if err != nil {
		return fmt.Errorf("error hashing existing manufacturer key: %w", err)
	}

	newMfgHash, err := hashPublicKey(newVoucher.Header.Val.ManufacturerKey)
	if err != nil {
		return fmt.Errorf("error hashing new manufacturer key: %w", err)
	}

	if existingMfgHash != newMfgHash {
		return fmt.Errorf("manufacturer key mismatch: GUID %x already registered with different manufacturer", newVoucher.Header.Val.GUID)
	}

	return nil
}

// checkFirstRegistrationLock rejects any replacement if the existing entry hasn't expired.
func checkFirstRegistrationLock(existingVoucher *Voucher) error {
	// The existence of a non-expired voucher means we should reject
	// (RVBlob already filtered out expired entries)
	return fmt.Errorf("GUID %x is locked to first registration until expiration", existingVoucher.Header.Val.GUID)
}

// checkOwnerKeyConsistency verifies that the owner key (final voucher entry) matches.
func checkOwnerKeyConsistency(newVoucher, existingVoucher *Voucher) error {
	existingOwnerKey, err := existingVoucher.OwnerPublicKey()
	if err != nil {
		return fmt.Errorf("error extracting existing owner key: %w", err)
	}

	newOwnerKey, err := newVoucher.OwnerPublicKey()
	if err != nil {
		return fmt.Errorf("error extracting new owner key: %w", err)
	}

	existingOwnerHash, err := hashCryptoPublicKey(existingOwnerKey)
	if err != nil {
		return fmt.Errorf("error hashing existing owner key: %w", err)
	}

	newOwnerHash, err := hashCryptoPublicKey(newOwnerKey)
	if err != nil {
		return fmt.Errorf("error hashing new owner key: %w", err)
	}

	if existingOwnerHash != newOwnerHash {
		return fmt.Errorf("owner key mismatch: GUID %x already registered with different owner", newVoucher.Header.Val.GUID)
	}

	return nil
}

// hashPublicKey computes a SHA-256 hash of a protocol.PublicKey for comparison.
// Uses PKIX encoding for consistency with hashCryptoPublicKey().
func hashPublicKey(key protocol.PublicKey) (string, error) {
	// Extract crypto.PublicKey and use PKIX encoding for consistency
	cryptoKey, err := key.Public()
	if err != nil {
		return "", fmt.Errorf("error extracting public key: %w", err)
	}
	return hashCryptoPublicKey(cryptoKey)
}

// hashCryptoPublicKey computes a SHA-256 hash of a crypto.PublicKey for comparison.
// Use x509 marshaling for consistent key encoding
func hashCryptoPublicKey(key crypto.PublicKey) (string, error) {
	// Use x509 marshaling for consistent key encoding
	keyBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", fmt.Errorf("error marshaling public key: %w", err)
	}
	hash := sha256.Sum256(keyBytes)
	return fmt.Sprintf("%x", hash), nil
}

// RVBlobWithPolicy wraps a RendezvousBlobPersistentState to enforce a replacement policy.
type RVBlobWithPolicy struct {
	Storage RendezvousBlobPersistentState
	Policy  VoucherReplacementPolicy
}

// SetRVBlob enforces the replacement policy before storing the blob.
func (r *RVBlobWithPolicy) SetRVBlob(ctx context.Context, ov *Voucher, to1d *cose.Sign1[protocol.To1d, []byte], exp time.Time) error {
	// Check replacement policy
	if err := CheckVoucherReplacement(ctx, r.Policy, ov, r.Storage); err != nil {
		return fmt.Errorf("voucher replacement policy violation: %w", err)
	}

	// Policy check passed, proceed with storage
	return r.Storage.SetRVBlob(ctx, ov, to1d, exp)
}

// RVBlob delegates to the underlying storage.
func (r *RVBlobWithPolicy) RVBlob(ctx context.Context, guid protocol.GUID) (*cose.Sign1[protocol.To1d, []byte], *Voucher, error) {
	return r.Storage.RVBlob(ctx, guid)
}
