// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"testing"

	"github.com/fido-device-onboard/go-fdo"
)

func TestGenerateDelegate(t *testing.T) {
	// Generate owner key
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	// Generate delegate key
	delegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate delegate key: %v", err)
	}

	// Generate delegate certificate with onboard permission
	cert, err := fdo.GenerateDelegate(
		ownerKey,
		fdo.DelegateFlagRoot,
		delegateKey.Public(),
		"TestDelegate",
		"TestOwner",
		[]asn1.ObjectIdentifier{fdo.OIDPermitOnboardNewCred},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate delegate: %v", err)
	}

	if cert == nil {
		t.Fatal("expected certificate, got nil")
	}

	if cert.Subject.CommonName != "TestDelegate" {
		t.Errorf("expected subject CN 'TestDelegate', got %q", cert.Subject.CommonName)
	}
}

func TestVerifyDelegateChain(t *testing.T) {
	// Generate owner key
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	// Generate intermediate key
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate intermediate key: %v", err)
	}

	// Generate leaf delegate key
	leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate leaf key: %v", err)
	}

	// Use redirect OID which is stored in UnknownExtKeyUsage
	// Generate intermediate certificate (signed by owner)
	intermediateCert, err := fdo.GenerateDelegate(
		ownerKey,
		fdo.DelegateFlagRoot|fdo.DelegateFlagIntermediate,
		intermediateKey.Public(),
		"Intermediate",
		"Owner",
		[]asn1.ObjectIdentifier{fdo.OIDPermitRedirect},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate intermediate cert: %v", err)
	}

	// Generate leaf certificate (signed by intermediate)
	leafCert, err := fdo.GenerateDelegate(
		intermediateKey,
		0, // leaf
		leafKey.Public(),
		"Leaf",
		"Intermediate",
		[]asn1.ObjectIdentifier{fdo.OIDPermitRedirect},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate leaf cert: %v", err)
	}

	// Build chain (leaf first, then intermediate)
	chain := []*x509.Certificate{leafCert, intermediateCert}

	// Verify chain with redirect permission
	ownerPubKey := ownerKey.Public()
	err = fdo.VerifyDelegateChain(chain, &ownerPubKey, &fdo.OIDPermitRedirect)
	if err != nil {
		t.Errorf("delegate chain verification failed: %v", err)
	}
}

func TestVerifyDelegateChainWrongOwner(t *testing.T) {
	// Generate owner key
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	// Generate a different "wrong" owner key
	wrongOwnerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate wrong owner key: %v", err)
	}

	// Generate delegate key
	delegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate delegate key: %v", err)
	}

	// Generate delegate certificate (signed by owner)
	cert, err := fdo.GenerateDelegate(
		ownerKey,
		fdo.DelegateFlagRoot,
		delegateKey.Public(),
		"Delegate",
		"Owner",
		[]asn1.ObjectIdentifier{fdo.OIDPermitOnboardNewCred},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate delegate cert: %v", err)
	}

	// Verify chain with wrong owner - should fail
	chain := []*x509.Certificate{cert}
	wrongPubKey := wrongOwnerKey.Public()
	err = fdo.VerifyDelegateChain(chain, &wrongPubKey, &fdo.OIDPermitOnboardNewCred)
	if err == nil {
		t.Error("expected verification to fail with wrong owner key")
	}
}

func TestDelegateChainSummary(t *testing.T) {
	// Create mock certificates with common names
	cert1 := &x509.Certificate{}
	cert1.Subject.CommonName = "Leaf"
	cert2 := &x509.Certificate{}
	cert2.Subject.CommonName = "Intermediate"
	cert3 := &x509.Certificate{}
	cert3.Subject.CommonName = "Root"

	chain := []*x509.Certificate{cert1, cert2, cert3}
	summary := fdo.DelegateChainSummary(chain)

	expected := "Leaf->Intermediate->Root->"
	if summary != expected {
		t.Errorf("expected summary %q, got %q", expected, summary)
	}
}

// TestSelfSignedDelegateRejected verifies that a self-signed delegate certificate
// (not signed by the legitimate owner) is rejected during verification.
// This is a critical security test - without this check, an attacker could
// create their own delegate certificate and impersonate the owner.
func TestSelfSignedDelegateRejected(t *testing.T) {
	// Generate the legitimate owner key
	legitimateOwnerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate legitimate owner key: %v", err)
	}

	// Generate an attacker's key (used to self-sign a fake delegate)
	attackerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate attacker key: %v", err)
	}

	// Attacker creates a self-signed delegate certificate
	// (signed by attacker, NOT by the legitimate owner)
	selfSignedCert, err := fdo.GenerateDelegate(
		attackerKey, // Attacker signs with their own key
		fdo.DelegateFlagRoot,
		attackerKey.Public(), // Delegate key is also attacker's key
		"FakeDelegate",
		"FakeOwner",
		[]asn1.ObjectIdentifier{fdo.OIDPermitOnboardNewCred, fdo.OIDPermitOnboardReuseCred},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate self-signed cert: %v", err)
	}

	// Attempt to verify the self-signed delegate against the legitimate owner
	// This MUST fail - the delegate was not signed by the legitimate owner
	chain := []*x509.Certificate{selfSignedCert}
	legitimatePubKey := legitimateOwnerKey.Public()
	err = fdo.VerifyDelegateChain(chain, &legitimatePubKey, nil)
	if err == nil {
		t.Fatal("SECURITY FAILURE: self-signed delegate was accepted as valid for legitimate owner")
	}
	t.Logf("Correctly rejected self-signed delegate: %v", err)
}

// TestDelegateChainMissingPermission verifies that a delegate without the
// required permission OID is rejected.
func TestDelegateChainMissingPermission(t *testing.T) {
	// Generate owner key
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	// Generate delegate key
	delegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate delegate key: %v", err)
	}

	// Generate delegate certificate with ONLY redirect permission (no onboard)
	cert, err := fdo.GenerateDelegate(
		ownerKey,
		fdo.DelegateFlagRoot,
		delegateKey.Public(),
		"RedirectOnlyDelegate",
		"Owner",
		[]asn1.ObjectIdentifier{fdo.OIDPermitRedirect}, // Only redirect, no onboard
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate delegate cert: %v", err)
	}

	chain := []*x509.Certificate{cert}
	ownerPubKey := ownerKey.Public()

	// Verification with redirect permission should succeed
	err = fdo.VerifyDelegateChain(chain, &ownerPubKey, &fdo.OIDPermitRedirect)
	if err != nil {
		t.Errorf("delegate with redirect permission should pass redirect check: %v", err)
	}

	// Verification requiring onboard permission should fail
	err = fdo.VerifyDelegateChain(chain, &ownerPubKey, &fdo.OIDPermitOnboardNewCred)
	if err == nil {
		t.Error("delegate without onboard permission should fail onboard check")
	}
}
