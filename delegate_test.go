// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/fido-device-onboard/go-fdo/v2"
)

func TestGenerateDelegate(t *testing.T) {
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	delegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate delegate key: %v", err)
	}

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
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	intermediateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate intermediate key: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate leaf key: %v", err)
	}

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

	leafCert, err := fdo.GenerateDelegate(
		intermediateKey,
		0,
		leafKey.Public(),
		"Leaf",
		"Intermediate",
		[]asn1.ObjectIdentifier{fdo.OIDPermitRedirect},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate leaf cert: %v", err)
	}

	chain := []*x509.Certificate{leafCert, intermediateCert}

	ownerPubKey := ownerKey.Public()
	err = fdo.VerifyDelegateChain(chain, &ownerPubKey, &fdo.OIDPermitRedirect)
	if err != nil {
		t.Errorf("delegate chain verification failed: %v", err)
	}
}

func TestVerifyDelegateChainWrongOwner(t *testing.T) {
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	wrongOwnerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate wrong owner key: %v", err)
	}

	delegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate delegate key: %v", err)
	}

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

	chain := []*x509.Certificate{cert}
	wrongPubKey := wrongOwnerKey.Public()
	err = fdo.VerifyDelegateChain(chain, &wrongPubKey, &fdo.OIDPermitOnboardNewCred)
	if err == nil {
		t.Error("expected verification to fail with wrong owner key")
	}
}

func TestDelegateChainSummary(t *testing.T) {
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

func TestSelfSignedDelegateRejected(t *testing.T) {
	legitimateOwnerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate legitimate owner key: %v", err)
	}

	attackerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate attacker key: %v", err)
	}

	selfSignedCert, err := fdo.GenerateDelegate(
		attackerKey,
		fdo.DelegateFlagRoot,
		attackerKey.Public(),
		"FakeDelegate",
		"FakeOwner",
		[]asn1.ObjectIdentifier{fdo.OIDPermitOnboardNewCred, fdo.OIDPermitOnboardReuseCred},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate self-signed cert: %v", err)
	}

	chain := []*x509.Certificate{selfSignedCert}
	legitimatePubKey := legitimateOwnerKey.Public()
	err = fdo.VerifyDelegateChain(chain, &legitimatePubKey, nil)
	if err == nil {
		t.Fatal("SECURITY FAILURE: self-signed delegate was accepted as valid for legitimate owner")
	}
}

func TestDelegateChainMissingPermission(t *testing.T) {
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	delegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate delegate key: %v", err)
	}

	cert, err := fdo.GenerateDelegate(
		ownerKey,
		fdo.DelegateFlagRoot,
		delegateKey.Public(),
		"RedirectOnlyDelegate",
		"Owner",
		[]asn1.ObjectIdentifier{fdo.OIDPermitRedirect},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate delegate cert: %v", err)
	}

	chain := []*x509.Certificate{cert}
	ownerPubKey := ownerKey.Public()

	err = fdo.VerifyDelegateChain(chain, &ownerPubKey, &fdo.OIDPermitRedirect)
	if err != nil {
		t.Errorf("delegate with redirect permission should pass redirect check: %v", err)
	}

	err = fdo.VerifyDelegateChain(chain, &ownerPubKey, &fdo.OIDPermitOnboardNewCred)
	if err == nil {
		t.Error("delegate without onboard permission should fail onboard check")
	}
}

func TestDelegateCannotOnboardWithRedirectOnly(t *testing.T) {
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	delegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate delegate key: %v", err)
	}

	cert, err := fdo.GenerateDelegate(
		ownerKey,
		fdo.DelegateFlagRoot,
		delegateKey.Public(),
		"RedirectOnlyDelegate",
		"Owner",
		[]asn1.ObjectIdentifier{fdo.OIDPermitRedirect},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate delegate cert: %v", err)
	}

	chain := []*x509.Certificate{cert}

	if fdo.DelegateCanOnboard(chain) {
		t.Error("SECURITY FAILURE: DelegateCanOnboard returned true for redirect-only delegate")
	}

	if !fdo.DelegateCanRedirect(chain) {
		t.Error("DelegateCanRedirect should return true for redirect-only delegate")
	}
}

func TestDelegateWithAllPermissions(t *testing.T) {
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	delegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate delegate key: %v", err)
	}

	cert, err := fdo.GenerateDelegate(
		ownerKey,
		fdo.DelegateFlagRoot,
		delegateKey.Public(),
		"FullPermissionDelegate",
		"Owner",
		[]asn1.ObjectIdentifier{
			fdo.OIDPermitRedirect,
			fdo.OIDPermitOnboardNewCred,
			fdo.OIDPermitOnboardReuseCred,
			fdo.OIDPermitOnboardFdoDisable,
		},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate delegate cert: %v", err)
	}

	chain := []*x509.Certificate{cert}

	if !fdo.DelegateCanOnboard(chain) {
		t.Error("DelegateCanOnboard should return true")
	}
	if !fdo.DelegateCanReuseCred(chain) {
		t.Error("DelegateCanReuseCred should return true")
	}
	if !fdo.DelegateCanRedirect(chain) {
		t.Error("DelegateCanRedirect should return true")
	}
}

func TestVerifyDelegateChainRichIssuer(t *testing.T) {
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	delegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate delegate key: %v", err)
	}

	ownerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Owner",
			Organization: []string{"FDO"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}

	ownerDER, err := x509.CreateCertificate(rand.Reader, ownerTemplate, ownerTemplate, ownerKey.Public(), ownerKey)
	if err != nil {
		t.Fatalf("failed to create owner cert: %v", err)
	}
	ownerCert, err := x509.ParseCertificate(ownerDER)
	if err != nil {
		t.Fatalf("failed to parse owner cert: %v", err)
	}

	delegateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "FDO Delegate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{
			fdo.OIDPermitOnboardNewCred,
			fdo.OIDPermitOnboardReuseCred,
		},
	}

	delegateDER, err := x509.CreateCertificate(rand.Reader, delegateTemplate, ownerCert, delegateKey.Public(), ownerKey)
	if err != nil {
		t.Fatalf("failed to create delegate cert: %v", err)
	}
	delegateCert, err := x509.ParseCertificate(delegateDER)
	if err != nil {
		t.Fatalf("failed to parse delegate cert: %v", err)
	}

	chain := []*x509.Certificate{delegateCert}
	ownerPubKey := crypto.PublicKey(ownerKey.Public())
	err = fdo.VerifyDelegateChain(chain, &ownerPubKey, nil)
	if err != nil {
		t.Errorf("delegate chain verification failed with rich issuer DN: %v", err)
	}
}
