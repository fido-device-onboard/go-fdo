// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// mockRVBlobStorage is a simple in-memory storage for testing
type mockRVBlobStorage struct {
	blobs    map[protocol.GUID]*cose.Sign1[protocol.To1d, []byte]
	vouchers map[protocol.GUID]*fdo.Voucher
}

func newMockRVBlobStorage() *mockRVBlobStorage {
	return &mockRVBlobStorage{
		blobs:    make(map[protocol.GUID]*cose.Sign1[protocol.To1d, []byte]),
		vouchers: make(map[protocol.GUID]*fdo.Voucher),
	}
}

func (m *mockRVBlobStorage) SetRVBlob(ctx context.Context, ov *fdo.Voucher, to1d *cose.Sign1[protocol.To1d, []byte], exp time.Time) error {
	guid := ov.Header.Val.GUID
	m.blobs[guid] = to1d
	m.vouchers[guid] = ov
	return nil
}

func (m *mockRVBlobStorage) RVBlob(ctx context.Context, guid protocol.GUID) (*cose.Sign1[protocol.To1d, []byte], *fdo.Voucher, error) {
	blob, ok := m.blobs[guid]
	if !ok {
		return nil, nil, fdo.ErrNotFound
	}
	return blob, m.vouchers[guid], nil
}

// TestVoucherReplacementPolicies tests all 4 policies against 3 replacement scenarios
func TestVoucherReplacementPolicies(t *testing.T) {
	ctx := context.Background()

	// Generate keys for different manufacturers and owners
	mfgKeyA, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate manufacturer A key: %v", err)
	}
	mfgKeyB, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate manufacturer B key: %v", err)
	}
	ownerKeyA, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner A key: %v", err)
	}
	ownerKeyB, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner B key: %v", err)
	}

	// Shared GUID for all tests
	var guid protocol.GUID
	if _, err := rand.Read(guid[:]); err != nil {
		t.Fatalf("failed to generate GUID: %v", err)
	}

	// Helper to create a voucher with specific manufacturer and owner
	createVoucher := func(mfgKey, ownerKey *ecdsa.PrivateKey) *fdo.Voucher {
		// Create manufacturer public key
		mfgPubKey, err := protocol.NewPublicKey(protocol.Secp384r1KeyType, &mfgKey.PublicKey, false)
		if err != nil {
			t.Fatalf("failed to create manufacturer public key: %v", err)
		}

		// Create voucher header
		ovh := fdo.VoucherHeader{
			Version:         101,
			GUID:            guid,
			DeviceInfo:      "test-device",
			ManufacturerKey: *mfgPubKey,
		}

		// Create owner public key
		ownerPubKey, err := protocol.NewPublicKey(protocol.Secp384r1KeyType, &ownerKey.PublicKey, false)
		if err != nil {
			t.Fatalf("failed to create owner public key: %v", err)
		}

		// Create a minimal voucher entry
		entry := cose.Sign1Tag[fdo.VoucherEntryPayload, []byte]{
			Sign1: cose.Sign1[fdo.VoucherEntryPayload, []byte]{
				Payload: cbor.NewByteWrap(fdo.VoucherEntryPayload{
					PreviousHash: protocol.Hash{Algorithm: protocol.Sha384Hash, Value: make([]byte, 48)},
					HeaderHash:   protocol.Hash{Algorithm: protocol.Sha384Hash, Value: make([]byte, 48)},
					Extra:        nil,
					PublicKey:    *ownerPubKey,
				}),
				Signature: make([]byte, 96), // Dummy signature for testing
			},
		}

		return &fdo.Voucher{
			Version:   101,
			Header:    *cbor.NewBstr(ovh),
			Hmac:      protocol.Hmac{},
			CertChain: nil,
			Entries:   []cose.Sign1Tag[fdo.VoucherEntryPayload, []byte]{entry},
		}
	}

	// Create test vouchers
	// Scenario 1: Different manufacturer, different owner
	voucherMfgAOwnerA := createVoucher(mfgKeyA, ownerKeyA)
	voucherMfgBOwnerB := createVoucher(mfgKeyB, ownerKeyB)

	// Scenario 2: Same manufacturer, different owner
	voucherMfgAOwnerB := createVoucher(mfgKeyA, ownerKeyB)

	// Scenario 3: Same manufacturer, same owner (should always be allowed)
	voucherMfgAOwnerAV2 := createVoucher(mfgKeyA, ownerKeyA)

	// Test matrix: 3 scenarios × 4 policies = 12 tests
	tests := []struct {
		name            string
		policy          fdo.VoucherReplacementPolicy
		existingVoucher *fdo.Voucher
		newVoucher      *fdo.Voucher
		shouldPass      bool
		description     string
	}{
		// Policy 0: Allow Any (all scenarios should pass)
		{
			name:            "Policy0_DifferentMfgDifferentOwner",
			policy:          fdo.RVPolicyAllowAny,
			existingVoucher: voucherMfgAOwnerA,
			newVoucher:      voucherMfgBOwnerB,
			shouldPass:      true,
			description:     "Option 0 allows replacement from different manufacturer and owner",
		},
		{
			name:            "Policy0_SameMfgDifferentOwner",
			policy:          fdo.RVPolicyAllowAny,
			existingVoucher: voucherMfgAOwnerA,
			newVoucher:      voucherMfgAOwnerB,
			shouldPass:      true,
			description:     "Option 0 allows replacement from same manufacturer, different owner",
		},
		{
			name:            "Policy0_SameMfgSameOwner",
			policy:          fdo.RVPolicyAllowAny,
			existingVoucher: voucherMfgAOwnerA,
			newVoucher:      voucherMfgAOwnerAV2,
			shouldPass:      true,
			description:     "Option 0 allows replacement from same manufacturer and owner",
		},

		// Policy 1: Manufacturer Key Consistency
		{
			name:            "Policy1_DifferentMfgDifferentOwner",
			policy:          fdo.RVPolicyManufacturerKeyConsistency,
			existingVoucher: voucherMfgAOwnerA,
			newVoucher:      voucherMfgBOwnerB,
			shouldPass:      false,
			description:     "Option 1 rejects replacement from different manufacturer",
		},
		{
			name:            "Policy1_SameMfgDifferentOwner",
			policy:          fdo.RVPolicyManufacturerKeyConsistency,
			existingVoucher: voucherMfgAOwnerA,
			newVoucher:      voucherMfgAOwnerB,
			shouldPass:      true,
			description:     "Option 1 allows replacement from same manufacturer, different owner",
		},
		{
			name:            "Policy1_SameMfgSameOwner",
			policy:          fdo.RVPolicyManufacturerKeyConsistency,
			existingVoucher: voucherMfgAOwnerA,
			newVoucher:      voucherMfgAOwnerAV2,
			shouldPass:      true,
			description:     "Option 1 allows replacement from same manufacturer and owner",
		},

		// Policy 2: First Registration Lock
		{
			name:            "Policy2_DifferentMfgDifferentOwner",
			policy:          fdo.RVPolicyFirstRegistrationLock,
			existingVoucher: voucherMfgAOwnerA,
			newVoucher:      voucherMfgBOwnerB,
			shouldPass:      false,
			description:     "Option 2 rejects all replacements (different manufacturer)",
		},
		{
			name:            "Policy2_SameMfgDifferentOwner",
			policy:          fdo.RVPolicyFirstRegistrationLock,
			existingVoucher: voucherMfgAOwnerA,
			newVoucher:      voucherMfgAOwnerB,
			shouldPass:      false,
			description:     "Option 2 rejects all replacements (same manufacturer, different owner)",
		},
		{
			name:            "Policy2_SameMfgSameOwner",
			policy:          fdo.RVPolicyFirstRegistrationLock,
			existingVoucher: voucherMfgAOwnerA,
			newVoucher:      voucherMfgAOwnerAV2,
			shouldPass:      false,
			description:     "Option 2 rejects all replacements (even same manufacturer and owner)",
		},

		// Policy 3: Owner Key Consistency
		{
			name:            "Policy3_DifferentMfgDifferentOwner",
			policy:          fdo.RVPolicyOwnerKeyConsistency,
			existingVoucher: voucherMfgAOwnerA,
			newVoucher:      voucherMfgBOwnerB,
			shouldPass:      false,
			description:     "Option 3 rejects replacement from different owner (even if different manufacturer)",
		},
		{
			name:            "Policy3_SameMfgDifferentOwner",
			policy:          fdo.RVPolicyOwnerKeyConsistency,
			existingVoucher: voucherMfgAOwnerA,
			newVoucher:      voucherMfgAOwnerB,
			shouldPass:      false,
			description:     "Option 3 rejects replacement from different owner (same manufacturer)",
		},
		{
			name:            "Policy3_SameMfgSameOwner",
			policy:          fdo.RVPolicyOwnerKeyConsistency,
			existingVoucher: voucherMfgAOwnerA,
			newVoucher:      voucherMfgAOwnerAV2,
			shouldPass:      true,
			description:     "Option 3 allows replacement from same owner",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create in-memory storage with existing voucher
			storage := newMockRVBlobStorage()

			// Register existing voucher
			to1d := &cose.Sign1[protocol.To1d, []byte]{
				Payload: cbor.NewByteWrap(protocol.To1d{
					RV: []protocol.RvTO2Addr{},
					To0dHash: protocol.Hash{
						Algorithm: protocol.Sha256Hash,
						Value:     make([]byte, 32),
					},
				}),
			}
			if err := storage.SetRVBlob(ctx, tt.existingVoucher, to1d, time.Now().Add(time.Hour)); err != nil {
				t.Fatalf("failed to set initial RV blob: %v", err)
			}

			// Attempt replacement with policy check
			err := fdo.CheckVoucherReplacement(ctx, tt.policy, tt.newVoucher, storage)

			// Verify result matches expectation
			if tt.shouldPass {
				if err != nil {
					t.Errorf("%s: expected replacement to pass but got error: %v", tt.description, err)
				}
			} else {
				if err == nil {
					t.Errorf("%s: expected replacement to fail but it passed", tt.description)
				} else {
					t.Logf("%s: correctly rejected with error: %v", tt.description, err)
				}
			}
		})
	}
}

// TestFirstRegistrationAllowed tests that first registration is always allowed
func TestFirstRegistrationAllowed(t *testing.T) {
	ctx := context.Background()

	// Generate a simple voucher
	mfgKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	var guid protocol.GUID
	if _, err := rand.Read(guid[:]); err != nil {
		t.Fatalf("failed to generate GUID: %v", err)
	}

	mfgPubKey, err := protocol.NewPublicKey(protocol.Secp384r1KeyType, &mfgKey.PublicKey, false)
	if err != nil {
		t.Fatalf("failed to create public key: %v", err)
	}

	ownerPubKey, err := protocol.NewPublicKey(protocol.Secp384r1KeyType, &ownerKey.PublicKey, false)
	if err != nil {
		t.Fatalf("failed to create owner public key: %v", err)
	}

	// Create minimal voucher entry
	entry := cose.Sign1Tag[fdo.VoucherEntryPayload, []byte]{
		Sign1: cose.Sign1[fdo.VoucherEntryPayload, []byte]{
			Payload: cbor.NewByteWrap(fdo.VoucherEntryPayload{
				PreviousHash: protocol.Hash{Algorithm: protocol.Sha384Hash, Value: make([]byte, 48)},
				HeaderHash:   protocol.Hash{Algorithm: protocol.Sha384Hash, Value: make([]byte, 48)},
				Extra:        nil,
				PublicKey:    *ownerPubKey,
			}),
			Signature: make([]byte, 96),
		},
	}

	voucher := &fdo.Voucher{
		Version: 101,
		Header: *cbor.NewBstr(fdo.VoucherHeader{
			Version:         101,
			GUID:            guid,
			DeviceInfo:      "test-device",
			ManufacturerKey: *mfgPubKey,
		}),
		Hmac:      protocol.Hmac{},
		CertChain: nil,
		Entries:   []cose.Sign1Tag[fdo.VoucherEntryPayload, []byte]{entry},
	}

	// Test all policies - first registration should always be allowed
	policies := []fdo.VoucherReplacementPolicy{
		fdo.RVPolicyAllowAny,
		fdo.RVPolicyManufacturerKeyConsistency,
		fdo.RVPolicyFirstRegistrationLock,
		fdo.RVPolicyOwnerKeyConsistency,
	}

	for _, policy := range policies {
		t.Run(policy.String(), func(t *testing.T) {
			storage := newMockRVBlobStorage()

			// First registration should always succeed
			err := fdo.CheckVoucherReplacement(ctx, policy, voucher, storage)
			if err != nil {
				t.Errorf("policy %s rejected first registration: %v", policy, err)
			}
		})
	}
}
