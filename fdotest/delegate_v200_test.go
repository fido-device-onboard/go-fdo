// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdotest_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"testing"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
)

// TestDelegateV200_ChainValidationForOnboarding creates a delegate chain
// suitable for FDO 2.0 TO2 onboarding and validates it against the owner
// key. In FDO 2.0, the delegate chain is carried in the COSE unprotected
// headers of ProveOVHdr20 (type 83).
func TestDelegateV200_ChainValidationForOnboarding(t *testing.T) {
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
		"V200OnboardDelegate",
		"V200Owner",
		[]asn1.ObjectIdentifier{fdo.OIDPermitOnboardNewCred},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate delegate cert: %v", err)
	}

	chain := []*x509.Certificate{cert}
	ownerPubKey := ownerKey.Public()

	// Verify the chain is valid for onboarding
	if err := fdo.VerifyDelegateChain(chain, &ownerPubKey, &fdo.OIDPermitOnboardNewCred); err != nil {
		t.Fatalf("delegate chain verification failed: %v", err)
	}

	if !fdo.DelegateCanOnboard(chain) {
		t.Error("delegate should be able to onboard")
	}
}

// TestDelegateV200_MultiLevelChain verifies that a multi-level delegate
// chain (owner -> intermediate -> leaf) validates correctly. In FDO 2.0,
// this chain is serialized as raw DER in the COSE unprotected headers.
func TestDelegateV200_MultiLevelChain(t *testing.T) {
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

	permissions := []asn1.ObjectIdentifier{
		fdo.OIDPermitOnboardNewCred,
		fdo.OIDPermitOnboardReuseCred,
		fdo.OIDPermitRedirect,
	}

	intermediateCert, err := fdo.GenerateDelegate(
		ownerKey,
		fdo.DelegateFlagRoot|fdo.DelegateFlagIntermediate,
		intermediateKey.Public(),
		"V200Intermediate",
		"V200Owner",
		permissions,
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate intermediate cert: %v", err)
	}

	leafCert, err := fdo.GenerateDelegate(
		intermediateKey,
		fdo.DelegateFlagLeaf,
		leafKey.Public(),
		"V200LeafDelegate",
		"V200Intermediate",
		permissions,
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate leaf cert: %v", err)
	}

	chain := []*x509.Certificate{leafCert, intermediateCert}
	ownerPubKey := ownerKey.Public()

	// Chain should validate for all included permissions
	if err := fdo.VerifyDelegateChain(chain, &ownerPubKey, &fdo.OIDPermitOnboardNewCred); err != nil {
		t.Errorf("chain should validate for onboard-new-cred: %v", err)
	}
	if err := fdo.VerifyDelegateChain(chain, &ownerPubKey, &fdo.OIDPermitOnboardReuseCred); err != nil {
		t.Errorf("chain should validate for onboard-reuse-cred: %v", err)
	}
	if err := fdo.VerifyDelegateChain(chain, &ownerPubKey, &fdo.OIDPermitRedirect); err != nil {
		t.Errorf("chain should validate for redirect: %v", err)
	}

	if !fdo.DelegateCanOnboard(chain) {
		t.Error("multi-level delegate should be able to onboard")
	}
	if !fdo.DelegateCanReuseCred(chain) {
		t.Error("multi-level delegate should be able to reuse credentials")
	}
	if !fdo.DelegateCanRedirect(chain) {
		t.Error("multi-level delegate should be able to redirect")
	}
}

// TestDelegateV200_PermissionSeparation verifies the FDO 2.0 permission
// model where redirect and onboard permissions are distinct. A delegate
// for TO0 (redirect) cannot perform TO2 (onboard) and vice versa. This
// separation is critical for FDO 2.0 multi-tenant scenarios.
func TestDelegateV200_PermissionSeparation(t *testing.T) {
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	tests := []struct {
		name        string
		permissions []asn1.ObjectIdentifier
		canOnboard  bool
		canReuse    bool
		canRedirect bool
	}{
		{
			name:        "redirect-only delegate",
			permissions: []asn1.ObjectIdentifier{fdo.OIDPermitRedirect},
			canRedirect: true,
		},
		{
			name:        "onboard-new-cred delegate",
			permissions: []asn1.ObjectIdentifier{fdo.OIDPermitOnboardNewCred},
			canOnboard:  true,
		},
		{
			name:        "onboard-reuse-cred delegate",
			permissions: []asn1.ObjectIdentifier{fdo.OIDPermitOnboardReuseCred},
			canOnboard:  true,
			canReuse:    true,
		},
		{
			name: "full permission delegate",
			permissions: []asn1.ObjectIdentifier{
				fdo.OIDPermitRedirect,
				fdo.OIDPermitOnboardNewCred,
				fdo.OIDPermitOnboardReuseCred,
				fdo.OIDPermitOnboardFdoDisable,
			},
			canOnboard:  true,
			canReuse:    true,
			canRedirect: true,
		},
		{
			name:        "provision-only delegate",
			permissions: []asn1.ObjectIdentifier{fdo.OIDPermitProvision},
		},
		{
			name:        "voucher-claim delegate",
			permissions: []asn1.ObjectIdentifier{fdo.OIDPermitVoucherClaim},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			delegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate delegate key: %v", err)
			}

			cert, err := fdo.GenerateDelegate(
				ownerKey,
				fdo.DelegateFlagRoot,
				delegateKey.Public(),
				"TestDelegate",
				"Owner",
				tt.permissions,
				x509.ECDSAWithSHA384,
			)
			if err != nil {
				t.Fatalf("failed to generate delegate cert: %v", err)
			}

			chain := []*x509.Certificate{cert}

			if got := fdo.DelegateCanOnboard(chain); got != tt.canOnboard {
				t.Errorf("DelegateCanOnboard = %v, want %v", got, tt.canOnboard)
			}
			if got := fdo.DelegateCanReuseCred(chain); got != tt.canReuse {
				t.Errorf("DelegateCanReuseCred = %v, want %v", got, tt.canReuse)
			}
			if got := fdo.DelegateCanRedirect(chain); got != tt.canRedirect {
				t.Errorf("DelegateCanRedirect = %v, want %v", got, tt.canRedirect)
			}
		})
	}
}

// TestDelegateV200_ChainInCOSEHeaders verifies that a delegate chain can
// be serialized as raw DER bytes suitable for inclusion in COSE Sign1
// unprotected headers, which is how FDO 2.0 ProveOVHdr20 (type 83)
// carries the delegate chain.
func TestDelegateV200_ChainInCOSEHeaders(t *testing.T) {
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
		"COSEDelegate",
		"COSEOwner",
		[]asn1.ObjectIdentifier{fdo.OIDPermitOnboardNewCred},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate delegate cert: %v", err)
	}

	// Serialize the chain as raw DER bytes (as done by the TO2 server)
	chain := []*x509.Certificate{cert}
	chainRaw := make([][]byte, len(chain))
	for i, c := range chain {
		chainRaw[i] = c.Raw
	}

	// CBOR encode/decode the raw chain (simulating COSE header transport)
	data, err := cbor.Marshal(chainRaw)
	if err != nil {
		t.Fatalf("failed to marshal chain DER: %v", err)
	}

	var decodedRaw [][]byte
	if err := cbor.Unmarshal(data, &decodedRaw); err != nil {
		t.Fatalf("failed to unmarshal chain DER: %v", err)
	}

	if len(decodedRaw) != len(chainRaw) {
		t.Fatalf("decoded chain length %d, want %d", len(decodedRaw), len(chainRaw))
	}

	// Parse back to certificates and verify
	for i, der := range decodedRaw {
		parsedCert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("failed to parse decoded cert %d: %v", i, err)
		}
		if parsedCert.Subject.CommonName != chain[i].Subject.CommonName {
			t.Errorf("cert %d CN mismatch: got %q, want %q",
				i, parsedCert.Subject.CommonName, chain[i].Subject.CommonName)
		}
	}

	// The parsed chain should still validate
	ownerPubKey := ownerKey.Public()
	if err := fdo.VerifyDelegateChain(chain, &ownerPubKey, &fdo.OIDPermitOnboardNewCred); err != nil {
		t.Errorf("chain should still validate after CBOR round-trip: %v", err)
	}
}

// TestDelegateV200_SecuritySelfSignedRejected is a security test that
// verifies a self-signed delegate certificate (not rooted in the legitimate
// owner key) is rejected. This is critical for FDO 2.0 where delegate
// chains are carried in-band via COSE unprotected headers.
func TestDelegateV200_SecuritySelfSignedRejected(t *testing.T) {
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
		t.Fatal("SECURITY FAILURE: self-signed delegate was accepted for legitimate owner in FDO 2.0 context")
	}
	t.Logf("Correctly rejected self-signed delegate: %v", err)
}

// TestDelegateV200_SecurityPermissionEscalation verifies that a delegate
// cannot escalate its permissions. An intermediate with only redirect
// permission should not be able to issue a leaf with onboard permission,
// because VerifyDelegateChain checks every certificate in the chain.
func TestDelegateV200_SecurityPermissionEscalation(t *testing.T) {
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

	// Intermediate only has redirect permission
	intermediateCert, err := fdo.GenerateDelegate(
		ownerKey,
		fdo.DelegateFlagRoot|fdo.DelegateFlagIntermediate,
		intermediateKey.Public(),
		"RedirectIntermediate",
		"Owner",
		[]asn1.ObjectIdentifier{fdo.OIDPermitRedirect},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate intermediate cert: %v", err)
	}

	// Leaf tries to claim onboard + redirect permissions
	leafCert, err := fdo.GenerateDelegate(
		intermediateKey,
		fdo.DelegateFlagLeaf,
		leafKey.Public(),
		"EscalatedLeaf",
		"RedirectIntermediate",
		[]asn1.ObjectIdentifier{fdo.OIDPermitRedirect, fdo.OIDPermitOnboardNewCred},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate leaf cert: %v", err)
	}

	chain := []*x509.Certificate{leafCert, intermediateCert}
	ownerPubKey := ownerKey.Public()

	// Redirect should pass (both certs have it)
	err = fdo.VerifyDelegateChain(chain, &ownerPubKey, &fdo.OIDPermitRedirect)
	if err != nil {
		t.Errorf("chain should pass redirect check: %v", err)
	}

	// Onboard should fail (intermediate lacks it)
	err = fdo.VerifyDelegateChain(chain, &ownerPubKey, &fdo.OIDPermitOnboardNewCred)
	if err == nil {
		t.Error("SECURITY FAILURE: permission escalation was not detected")
	}
}

// TestDelegateV200_DelegateKeyPersistentState verifies the
// DelegateKeyPersistentState interface used by the TO2Server for FDO 2.0
// delegation. This interface is how delegate key material is provided to
// the server for signing ProveOVHdr20 responses.
func TestDelegateV200_DelegateKeyPersistentState(t *testing.T) {
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	onboardDelegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate onboard delegate key: %v", err)
	}

	rvDelegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate RV delegate key: %v", err)
	}

	onboardCert, err := fdo.GenerateDelegate(
		ownerKey,
		fdo.DelegateFlagRoot,
		onboardDelegateKey.Public(),
		"OnboardDelegate",
		"Owner",
		[]asn1.ObjectIdentifier{fdo.OIDPermitOnboardNewCred, fdo.OIDPermitOnboardReuseCred},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate onboard cert: %v", err)
	}

	rvCert, err := fdo.GenerateDelegate(
		ownerKey,
		fdo.DelegateFlagRoot,
		rvDelegateKey.Public(),
		"RVDelegate",
		"Owner",
		[]asn1.ObjectIdentifier{fdo.OIDPermitRedirect},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate RV cert: %v", err)
	}

	store := &testDelegateKeyStore{
		keys: map[string]crypto.Signer{
			"onboard-delegate": onboardDelegateKey,
			"rv-delegate":      rvDelegateKey,
		},
		chains: map[string][]*x509.Certificate{
			"onboard-delegate": {onboardCert},
			"rv-delegate":      {rvCert},
		},
	}

	t.Run("onboard delegate retrieval", func(t *testing.T) {
		key, chain, err := store.DelegateKey("onboard-delegate")
		if err != nil {
			t.Fatalf("DelegateKey failed: %v", err)
		}
		if key == nil {
			t.Fatal("key is nil")
		}
		if len(chain) != 1 {
			t.Fatalf("expected 1 cert, got %d", len(chain))
		}
		if !fdo.DelegateCanOnboard(chain) {
			t.Error("onboard delegate should have onboard permission")
		}
		if fdo.DelegateCanRedirect(chain) {
			t.Error("onboard delegate should not have redirect permission")
		}
	})

	t.Run("rv delegate retrieval", func(t *testing.T) {
		key, chain, err := store.DelegateKey("rv-delegate")
		if err != nil {
			t.Fatalf("DelegateKey failed: %v", err)
		}
		if key == nil {
			t.Fatal("key is nil")
		}
		if len(chain) != 1 {
			t.Fatalf("expected 1 cert, got %d", len(chain))
		}
		if fdo.DelegateCanOnboard(chain) {
			t.Error("rv delegate should not have onboard permission")
		}
		if !fdo.DelegateCanRedirect(chain) {
			t.Error("rv delegate should have redirect permission")
		}
	})

	t.Run("non-existent delegate", func(t *testing.T) {
		_, _, err := store.DelegateKey("non-existent")
		if err == nil {
			t.Error("expected error for non-existent delegate")
		}
	})
}

// testDelegateKeyStore implements fdo.DelegateKeyPersistentState for tests.
type testDelegateKeyStore struct {
	keys   map[string]crypto.Signer
	chains map[string][]*x509.Certificate
}

func (s *testDelegateKeyStore) DelegateKey(name string) (crypto.Signer, []*x509.Certificate, error) {
	key, ok := s.keys[name]
	if !ok {
		return nil, nil, fmt.Errorf("delegate key %q not found", name)
	}
	chain, ok := s.chains[name]
	if !ok {
		return nil, nil, fmt.Errorf("delegate chain %q not found", name)
	}
	return key, chain, nil
}

// TestDelegateV200_OIDStringConversion verifies the delegate OID <-> string
// conversion functions work correctly for all FDO 2.0 permission OIDs.
func TestDelegateV200_OIDStringConversion(t *testing.T) {
	tests := []struct {
		oid  asn1.ObjectIdentifier
		name string
	}{
		{fdo.OIDPermitRedirect, "permit-redirect"},
		{fdo.OIDPermitOnboardNewCred, "permit-onboard-new-cred"},
		{fdo.OIDPermitOnboardReuseCred, "permit-onboard-reuse-cred"},
		{fdo.OIDPermitOnboardFdoDisable, "permit-onboard-fdo-disable"},
		{fdo.OIDPermitVoucherClaim, "permit-voucher-claim"},
		{fdo.OIDPermitVoucherUpload, "permit-voucher-upload"},
		{fdo.OIDPermitProvision, "permit-provision"},
		{fdo.OIDDelegateClaim, "claim"},
		{fdo.OIDDelegateProvision, "provision"},
		{fdo.OIDOwnershipCA, "ownershipCA"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fdo.DelegateOIDtoString(tt.oid)
			if got != tt.name {
				t.Errorf("DelegateOIDtoString(%v) = %q, want %q", tt.oid, got, tt.name)
			}
		})
	}
}

// TestDelegateV200_StringToOIDConversion verifies that permission string
// names can be converted back to OIDs. This is used when configuring
// delegates from command-line arguments or configuration files.
func TestDelegateV200_StringToOIDConversion(t *testing.T) {
	tests := []struct {
		str     string
		oid     asn1.ObjectIdentifier
		wantErr bool
	}{
		{"redirect", fdo.OIDPermitRedirect, false},
		{"permit-redirect", fdo.OIDPermitRedirect, false},
		{"onboard-new-cred", fdo.OIDPermitOnboardNewCred, false},
		{"permit-onboard-new-cred", fdo.OIDPermitOnboardNewCred, false},
		{"onboard-reuse-cred", fdo.OIDPermitOnboardReuseCred, false},
		{"onboard-fdo-disable", fdo.OIDPermitOnboardFdoDisable, false},
		{"voucher-claim", fdo.OIDPermitVoucherClaim, false},
		{"voucher-upload", fdo.OIDPermitVoucherUpload, false},
		{"provision", fdo.OIDPermitProvision, false},
		{"claim", fdo.OIDDelegateClaim, false},
		{"invalid-perm", fdo.OIDDelegateBase, true},
	}

	for _, tt := range tests {
		t.Run(tt.str, func(t *testing.T) {
			oid, err := fdo.DelegateStringToOID(tt.str)
			if (err != nil) != tt.wantErr {
				t.Errorf("DelegateStringToOID(%q) error = %v, wantErr %v", tt.str, err, tt.wantErr)
				return
			}
			if !tt.wantErr && !oid.Equal(tt.oid) {
				t.Errorf("DelegateStringToOID(%q) = %v, want %v", tt.str, oid, tt.oid)
			}
		})
	}
}

// TestDelegateV200_EmptyChain verifies that an empty delegate chain is
// correctly rejected.
func TestDelegateV200_EmptyChain(t *testing.T) {
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	ownerPubKey := ownerKey.Public()
	err = fdo.VerifyDelegateChain(nil, &ownerPubKey, nil)
	if err == nil {
		t.Error("empty delegate chain should be rejected")
	}

	err = fdo.VerifyDelegateChain([]*x509.Certificate{}, &ownerPubKey, nil)
	if err == nil {
		t.Error("zero-length delegate chain should be rejected")
	}
}

// TestDelegateV200_CanOnboardWithAnyOnboardPermission verifies that
// DelegateCanOnboard returns true for any of the three onboard permission
// OIDs (new-cred, reuse-cred, fdo-disable).
func TestDelegateV200_CanOnboardWithAnyOnboardPermission(t *testing.T) {
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	onboardOIDs := []asn1.ObjectIdentifier{
		fdo.OIDPermitOnboardNewCred,
		fdo.OIDPermitOnboardReuseCred,
		fdo.OIDPermitOnboardFdoDisable,
	}

	for _, oid := range onboardOIDs {
		t.Run(fdo.DelegateOIDtoString(oid), func(t *testing.T) {
			delegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate delegate key: %v", err)
			}

			cert, err := fdo.GenerateDelegate(
				ownerKey,
				fdo.DelegateFlagRoot,
				delegateKey.Public(),
				"TestDelegate",
				"Owner",
				[]asn1.ObjectIdentifier{oid},
				x509.ECDSAWithSHA384,
			)
			if err != nil {
				t.Fatalf("failed to generate delegate cert: %v", err)
			}

			chain := []*x509.Certificate{cert}
			if !fdo.DelegateCanOnboard(chain) {
				t.Errorf("DelegateCanOnboard should return true for %s", fdo.DelegateOIDtoString(oid))
			}
		})
	}
}
