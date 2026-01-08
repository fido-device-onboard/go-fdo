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
