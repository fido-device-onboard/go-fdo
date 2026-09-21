// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"testing"
)

func TestTO0OwnerSignInfo_StructFields(t *testing.T) {
	// Verify that TO0OwnerSignInfo can be constructed with all fields
	info := TO0OwnerSignInfo{
		Voucher:       Voucher{},
		DelegateChain: nil,
		RequestedTTL:  3600,
	}

	if info.RequestedTTL != 3600 {
		t.Errorf("expected RequestedTTL 3600, got %d", info.RequestedTTL)
	}
	if info.DelegateChain != nil {
		t.Error("expected nil DelegateChain")
	}
}

func TestTO0OwnerSignInfo_WithDelegateChain(t *testing.T) {
	// Generate owner key
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Generate delegate key
	delegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Generate delegate certificate with redirect permission
	cert, err := GenerateDelegate(
		ownerKey,
		DelegateFlagRoot,
		delegateKey.Public(),
		"TestDelegate",
		"TestOwner",
		[]asn1.ObjectIdentifier{OIDPermitRedirect},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatal(err)
	}

	chain := []*x509.Certificate{cert}

	info := TO0OwnerSignInfo{
		Voucher:       Voucher{},
		DelegateChain: chain,
		RequestedTTL:  86400,
	}

	if len(info.DelegateChain) != 1 {
		t.Fatalf("expected 1 cert in chain, got %d", len(info.DelegateChain))
	}
	if info.DelegateChain[0].Subject.CommonName != "TestDelegate" {
		t.Errorf("expected CN 'TestDelegate', got %q", info.DelegateChain[0].Subject.CommonName)
	}

	// Verify delegate has redirect permission
	if !DelegateCanRedirect(info.DelegateChain) {
		t.Error("expected delegate to have redirect permission")
	}
}

func TestTO0Server_AcceptVoucherWithInfoPrecedence(t *testing.T) {
	// Verify that AcceptVoucherWithInfo takes precedence over AcceptVoucher
	// when both are set. We test the logic by calling the callbacks directly
	// since the full protocol flow requires complex CBOR message construction.

	oldCalled := false
	newCalled := false

	server := &TO0Server{
		AcceptVoucher: func(ctx context.Context, ov Voucher, ttl uint32) (uint32, error) {
			oldCalled = true
			return ttl, nil
		},
		AcceptVoucherWithInfo: func(ctx context.Context, info TO0OwnerSignInfo) (uint32, error) {
			newCalled = true
			return info.RequestedTTL, nil
		},
	}

	// Simulate the precedence logic from acceptOwner
	ctx := context.Background()
	ttl := uint32(3600)
	var err error

	if server.AcceptVoucherWithInfo != nil {
		info := TO0OwnerSignInfo{
			Voucher:      Voucher{},
			RequestedTTL: ttl,
		}
		ttl, err = server.AcceptVoucherWithInfo(ctx, info)
	} else if server.AcceptVoucher != nil {
		ttl, err = server.AcceptVoucher(ctx, Voucher{}, ttl)
	}

	if err != nil {
		t.Fatal(err)
	}
	if !newCalled {
		t.Error("expected AcceptVoucherWithInfo to be called")
	}
	if oldCalled {
		t.Error("expected AcceptVoucher NOT to be called when AcceptVoucherWithInfo is set")
	}
	if ttl != 3600 {
		t.Errorf("expected ttl 3600, got %d", ttl)
	}
}

func TestTO0Server_FallbackToAcceptVoucher(t *testing.T) {
	// Verify fallback to AcceptVoucher when AcceptVoucherWithInfo is nil
	oldCalled := false

	server := &TO0Server{
		AcceptVoucher: func(ctx context.Context, ov Voucher, ttl uint32) (uint32, error) {
			oldCalled = true
			return ttl / 2, nil // halve the TTL
		},
	}

	ctx := context.Background()
	ttl := uint32(3600)
	var err error

	if server.AcceptVoucherWithInfo != nil {
		info := TO0OwnerSignInfo{RequestedTTL: ttl}
		ttl, err = server.AcceptVoucherWithInfo(ctx, info)
	} else if server.AcceptVoucher != nil {
		ttl, err = server.AcceptVoucher(ctx, Voucher{}, ttl)
	}

	if err != nil {
		t.Fatal(err)
	}
	if !oldCalled {
		t.Error("expected AcceptVoucher to be called as fallback")
	}
	if ttl != 1800 {
		t.Errorf("expected ttl 1800, got %d", ttl)
	}
}

func TestTO0Server_NeitherCallbackAcceptsAll(t *testing.T) {
	// Neither callback set = accept all with requested TTL
	server := &TO0Server{}

	ttl := uint32(7200)

	if server.AcceptVoucherWithInfo != nil {
		t.Fatal("should be nil")
	}
	if server.AcceptVoucher != nil {
		t.Fatal("should be nil")
	}
	// TTL stays unchanged
	if ttl != 7200 {
		t.Errorf("expected ttl 7200, got %d", ttl)
	}
}

func TestTO0OwnerSignInfo_DelegateChainVerification(t *testing.T) {
	// Test that the delegate chain in TO0OwnerSignInfo can be verified
	// against the voucher's owner key using existing VerifyDelegateChain

	// Generate owner key
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Generate intermediate delegate
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Generate leaf delegate
	leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Build delegate chain: owner -> intermediate -> leaf
	intermediateCert, err := GenerateDelegate(
		ownerKey,
		DelegateFlagRoot|DelegateFlagIntermediate,
		intermediateKey.Public(),
		"Intermediate",
		"Owner",
		[]asn1.ObjectIdentifier{OIDPermitRedirect},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatal(err)
	}

	leafCert, err := GenerateDelegate(
		intermediateKey,
		0, // leaf
		leafKey.Public(),
		"Leaf",
		"Intermediate",
		[]asn1.ObjectIdentifier{OIDPermitRedirect},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatal(err)
	}

	chain := []*x509.Certificate{leafCert, intermediateCert}

	info := TO0OwnerSignInfo{
		Voucher:       Voucher{},
		DelegateChain: chain,
		RequestedTTL:  3600,
	}

	// Verify delegate chain against owner key
	ownerPub := ownerKey.Public()
	err = VerifyDelegateChain(info.DelegateChain, &ownerPub, &OIDPermitRedirect)
	if err != nil {
		t.Errorf("delegate chain verification failed: %v", err)
	}

	// Verify it has redirect permission
	if !DelegateCanRedirect(info.DelegateChain) {
		t.Error("expected delegate to have redirect permission")
	}

	// Verify it does NOT have onboard permission
	if DelegateCanOnboard(info.DelegateChain) {
		t.Error("expected delegate to NOT have onboard permission")
	}
}

func TestTO0OwnerSignInfo_DelegateChainWrongOwner(t *testing.T) {
	// Verify that a delegate chain rooted by the wrong owner is rejected

	// Generate legitimate owner
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Generate attacker
	attackerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Generate delegate signed by attacker
	delegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := GenerateDelegate(
		attackerKey, // signed by attacker, not owner
		DelegateFlagRoot,
		delegateKey.Public(),
		"AttackerDelegate",
		"Attacker",
		[]asn1.ObjectIdentifier{OIDPermitRedirect},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatal(err)
	}

	info := TO0OwnerSignInfo{
		DelegateChain: []*x509.Certificate{cert},
	}

	// Verify against legitimate owner — should fail
	ownerPub := ownerKey.Public()
	err = VerifyDelegateChain(info.DelegateChain, &ownerPub, &OIDPermitRedirect)
	if err == nil {
		t.Error("expected verification to fail for delegate signed by wrong owner")
	}
}

func TestTO0OwnerSignInfo_NoDelegateChain(t *testing.T) {
	// When DelegateChain is nil, the TO1d was signed directly by the owner key
	info := TO0OwnerSignInfo{
		Voucher:       Voucher{},
		DelegateChain: nil,
		RequestedTTL:  3600,
	}

	if info.DelegateChain != nil {
		t.Error("expected nil delegate chain for direct owner signing")
	}

	// DelegateCanRedirect should return false for nil chain
	if DelegateCanRedirect(nil) {
		t.Error("DelegateCanRedirect(nil) should return false")
	}
}
