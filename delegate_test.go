// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/fido-device-onboard/go-fdo"
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

// TestSelfSignedDelegateRejected verifies that a self-signed delegate
// certificate (not signed by the legitimate owner) is rejected during
// verification. This is a critical security test.
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
	t.Logf("Correctly rejected self-signed delegate: %v", err)
}

// TestDelegateChainMissingPermission verifies that a delegate without the
// required permission OID is rejected.
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

// TestDelegateCannotOnboardWithRedirectOnly verifies that DelegateCanOnboard
// returns false for a delegate that only has redirect permission.
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

// TestDelegateChainIntermediateMissingPermission verifies that a multi-level
// delegate chain is rejected when an intermediate certificate lacks the
// required permission, even if the leaf has it.
func TestDelegateChainIntermediateMissingPermission(t *testing.T) {
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
		fdo.DelegateFlagIntermediate,
		intermediateKey.Public(),
		"IntermediateDelegate",
		"Owner",
		[]asn1.ObjectIdentifier{fdo.OIDPermitRedirect},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate intermediate cert: %v", err)
	}

	leafCert, err := fdo.GenerateDelegate(
		intermediateKey,
		fdo.DelegateFlagLeaf,
		leafKey.Public(),
		"LeafDelegate",
		"IntermediateDelegate",
		[]asn1.ObjectIdentifier{fdo.OIDPermitOnboardNewCred, fdo.OIDPermitRedirect},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate leaf cert: %v", err)
	}

	chain := []*x509.Certificate{leafCert, intermediateCert}
	ownerPubKey := ownerKey.Public()

	err = fdo.VerifyDelegateChain(chain, &ownerPubKey, &fdo.OIDPermitOnboardNewCred)
	if err == nil {
		t.Error("SECURITY FAILURE: chain with intermediate missing onboard permission was accepted")
	}

	err = fdo.VerifyDelegateChain(chain, &ownerPubKey, &fdo.OIDPermitRedirect)
	if err != nil {
		t.Errorf("chain should pass redirect check (both certs have redirect): %v", err)
	}
}

// TestDelegateChainRootMissingPermission verifies that a delegate chain is
// rejected when the root certificate lacks the required permission.
func TestDelegateChainRootMissingPermission(t *testing.T) {
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	rootDelegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate root delegate key: %v", err)
	}

	intermediateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate intermediate key: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate leaf key: %v", err)
	}

	rootCert, err := fdo.GenerateDelegate(
		ownerKey,
		fdo.DelegateFlagRoot,
		rootDelegateKey.Public(),
		"RootDelegate",
		"Owner",
		[]asn1.ObjectIdentifier{fdo.OIDPermitRedirect},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate root cert: %v", err)
	}

	intermediateCert, err := fdo.GenerateDelegate(
		rootDelegateKey,
		fdo.DelegateFlagIntermediate,
		intermediateKey.Public(),
		"IntermediateDelegate",
		"RootDelegate",
		[]asn1.ObjectIdentifier{fdo.OIDPermitOnboardNewCred, fdo.OIDPermitRedirect},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate intermediate cert: %v", err)
	}

	leafCert, err := fdo.GenerateDelegate(
		intermediateKey,
		fdo.DelegateFlagLeaf,
		leafKey.Public(),
		"LeafDelegate",
		"IntermediateDelegate",
		[]asn1.ObjectIdentifier{fdo.OIDPermitOnboardNewCred},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate leaf cert: %v", err)
	}

	chain := []*x509.Certificate{leafCert, intermediateCert, rootCert}
	ownerPubKey := ownerKey.Public()

	err = fdo.VerifyDelegateChain(chain, &ownerPubKey, &fdo.OIDPermitOnboardNewCred)
	if err == nil {
		t.Error("SECURITY FAILURE: chain with root missing onboard permission was accepted")
	}
}

// TestDelegateCannotReuseCred verifies that a delegate with
// onboard-new-cred permission but NOT onboard-reuse-cred cannot use
// credential reuse.
func TestDelegateCannotReuseCred(t *testing.T) {
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
		"NewCredOnlyDelegate",
		"Owner",
		[]asn1.ObjectIdentifier{fdo.OIDPermitOnboardNewCred},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate delegate cert: %v", err)
	}

	chain := []*x509.Certificate{cert}

	if !fdo.DelegateCanOnboard(chain) {
		t.Error("DelegateCanOnboard should return true for new-cred delegate")
	}

	if fdo.DelegateCanReuseCred(chain) {
		t.Error("SECURITY FAILURE: DelegateCanReuseCred returned true for delegate without reuse-cred permission")
	}
}

// TestDelegateWithReuseCred verifies that a delegate with
// onboard-reuse-cred permission can use credential reuse.
func TestDelegateWithReuseCred(t *testing.T) {
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
		"ReuseCredDelegate",
		"Owner",
		[]asn1.ObjectIdentifier{fdo.OIDPermitOnboardReuseCred},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate delegate cert: %v", err)
	}

	chain := []*x509.Certificate{cert}

	if !fdo.DelegateCanOnboard(chain) {
		t.Error("DelegateCanOnboard should return true for reuse-cred delegate")
	}

	if !fdo.DelegateCanReuseCred(chain) {
		t.Error("DelegateCanReuseCred should return true for delegate with reuse-cred permission")
	}
}

// TestDelegateCannotRedirectWithOnboardOnly verifies that a delegate with
// onboard permission but NOT redirect permission cannot perform TO0/TO1.
func TestDelegateCannotRedirectWithOnboardOnly(t *testing.T) {
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
		"OnboardOnlyDelegate",
		"Owner",
		[]asn1.ObjectIdentifier{fdo.OIDPermitOnboardNewCred, fdo.OIDPermitOnboardReuseCred},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate delegate cert: %v", err)
	}

	chain := []*x509.Certificate{cert}

	if !fdo.DelegateCanOnboard(chain) {
		t.Error("DelegateCanOnboard should return true for onboard delegate")
	}

	if fdo.DelegateCanRedirect(chain) {
		t.Error("SECURITY FAILURE: DelegateCanRedirect returned true for delegate without redirect permission")
	}
}

// TestDelegateWithAllPermissions verifies that a delegate with all permissions
// can perform all operations.
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

// TestVerifyDelegateChainRichIssuer verifies that delegate chain verification
// works when the owner certificate has a full distinguished name (C=, O=, CN=)
// rather than just a CommonName. This was a regression where the ephemeral root
// cert used only CommonName, causing a RawIssuer/RawSubject mismatch.
func TestVerifyDelegateChainRichIssuer(t *testing.T) {
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	delegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate delegate key: %v", err)
	}

	// Create an owner certificate with a rich subject (C, O, CN) matching
	// the CI test setup (/C=US/O=FDO/CN=Owner).
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

	// Create a delegate cert issued by the owner with the full DN as issuer.
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

	// The delegate cert's Issuer should have the full DN, not just CN.
	if delegateCert.Issuer.CommonName != "Owner" {
		t.Fatalf("expected issuer CN=Owner, got %q", delegateCert.Issuer.CommonName)
	}
	if len(delegateCert.Issuer.Organization) == 0 || delegateCert.Issuer.Organization[0] != "FDO" {
		t.Fatalf("expected issuer O=FDO, got %v", delegateCert.Issuer.Organization)
	}

	chain := []*x509.Certificate{delegateCert}
	ownerPubKey := ownerKey.Public()
	err = fdo.VerifyDelegateChain(chain, &ownerPubKey, nil)
	if err != nil {
		t.Errorf("delegate chain verification failed with rich issuer DN: %v", err)
	}
}
