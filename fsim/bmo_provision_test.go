// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"strings"
	"testing"

	fdo "github.com/fido-device-onboard/go-fdo"
)

// genECKey is a small helper for provisioning tests.
func genECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return k
}

// newDelegateCert mints a delegate certificate signed by ownerKey carrying the
// given permission OIDs.
func newDelegateCert(t *testing.T, ownerKey *ecdsa.PrivateKey, delegatePub *ecdsa.PublicKey, oids []asn1.ObjectIdentifier) *x509.Certificate {
	t.Helper()
	cert, err := fdo.GenerateDelegate(ownerKey, fdo.DelegateFlagLeaf, delegatePub, "test-delegate", "test-owner", oids, 0)
	if err != nil {
		t.Fatalf("GenerateDelegate: %v", err)
	}
	return cert
}

func TestOwnerSigner_ValidSignatureRoundtrip(t *testing.T) {
	owner := genECKey(t)
	signer := &OwnerSigner{Key: owner}

	payload := []byte("hello image-begin")
	signed, err := signer.Sign(payload, BMOContentTypeImageBegin)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	got, err := VerifyBmoSigned(signed, owner.Public(), BMOContentTypeImageBegin)
	if err != nil {
		t.Fatalf("VerifyBmoSigned: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload mismatch: got %q, want %q", got, payload)
	}
}

func TestVerifyBmoSigned_RejectsWrongOwnerKey(t *testing.T) {
	ownerA := genECKey(t)
	ownerB := genECKey(t)
	signer := &OwnerSigner{Key: ownerA}

	signed, err := signer.Sign([]byte("payload"), BMOContentTypeSet)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if _, err := VerifyBmoSigned(signed, ownerB.Public(), BMOContentTypeSet); err == nil {
		t.Fatal("expected verification failure with wrong owner key")
	}
}

func TestVerifyBmoSigned_ContentTypeMismatch(t *testing.T) {
	owner := genECKey(t)
	signer := &OwnerSigner{Key: owner}

	signed, err := signer.Sign([]byte("payload"), BMOContentTypeImageBegin)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := VerifyBmoSigned(signed, owner.Public(), BMOContentTypeSet); err == nil {
		t.Fatal("expected content-type mismatch error")
	}
}

func TestDelegateSigner_WithProvisionOID_Valid(t *testing.T) {
	owner := genECKey(t)
	delegate := genECKey(t)
	delegateCert := newDelegateCert(t, owner, &delegate.PublicKey, []asn1.ObjectIdentifier{fdo.OIDPermitProvision})

	signer := &DelegateSigner{Key: delegate, Chain: []*x509.Certificate{delegateCert}}
	signed, err := signer.Sign([]byte("delegate payload"), BMOContentTypeImageBegin)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	got, err := VerifyBmoSigned(signed, owner.Public(), BMOContentTypeImageBegin)
	if err != nil {
		t.Fatalf("VerifyBmoSigned: %v", err)
	}
	if string(got) != "delegate payload" {
		t.Fatalf("payload mismatch: got %q", got)
	}
}

func TestDelegateSigner_MissingProvisionOID_Rejected(t *testing.T) {
	owner := genECKey(t)
	delegate := genECKey(t)
	// Delegate carries only onboard permission — not provision.
	delegateCert := newDelegateCert(t, owner, &delegate.PublicKey, []asn1.ObjectIdentifier{fdo.OIDPermitOnboardNewCred})

	signer := &DelegateSigner{Key: delegate, Chain: []*x509.Certificate{delegateCert}}
	if _, err := signer.Sign([]byte("p"), BMOContentTypeImageBegin); err == nil {
		t.Fatal("expected signer to refuse chain without OIDPermitProvision")
	}
}

func TestVerifyBmoSigned_DelegateChainNotSignedByOwner(t *testing.T) {
	owner := genECKey(t)
	attacker := genECKey(t) // not the owner
	delegate := genECKey(t)

	// Delegate cert signed by attacker, not owner.
	delegateCert := newDelegateCert(t, attacker, &delegate.PublicKey, []asn1.ObjectIdentifier{fdo.OIDPermitProvision})

	// Manually construct a signer that bypasses the owner-side permission
	// check in DelegateSigner.Sign (which only inspects the leaf OIDs, not
	// the chain) and produces a signed message as an attacker would.
	signer := &DelegateSigner{Key: delegate, Chain: []*x509.Certificate{delegateCert}}
	signed, err := signer.Sign([]byte("evil"), BMOContentTypeImageBegin)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Device verifies using the legitimate owner's key — must reject.
	_, err = VerifyBmoSigned(signed, owner.Public(), BMOContentTypeImageBegin)
	if err == nil {
		t.Fatal("expected verification failure for chain not rooted in owner key")
	}
	if !strings.Contains(err.Error(), "delegate chain") && !strings.Contains(err.Error(), "signature") {
		t.Logf("rejection message: %v", err)
	}
}

func TestVerifyBmoSigned_Tampered(t *testing.T) {
	owner := genECKey(t)
	signer := &OwnerSigner{Key: owner}
	signed, err := signer.Sign([]byte("legit"), BMOContentTypeImageBegin)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Flip a byte near the end (signature area).
	signed[len(signed)-5] ^= 0x01
	if _, err := VerifyBmoSigned(signed, owner.Public(), BMOContentTypeImageBegin); err == nil {
		t.Fatal("expected verification failure on tampered signature")
	}
}

func TestVerifyBmoSigned_NoOwnerKey(t *testing.T) {
	owner := genECKey(t)
	signer := &OwnerSigner{Key: owner}
	signed, _ := signer.Sign([]byte("x"), BMOContentTypeSet)
	if _, err := VerifyBmoSigned(signed, nil, BMOContentTypeSet); err == nil {
		t.Fatal("expected error when ownerKey is nil")
	}
}
