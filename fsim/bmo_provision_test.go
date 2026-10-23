// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"bytes"
	"context"
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

// --- unwrapProvisioning tests for Model 2 (delegate channel authority) ---

// unsignedCBOR is a minimal valid CBOR map (empty map: 0xA0) that represents
// an unsigned provisioning message body (no COSE tag 18).
var unsignedCBOR = []byte{0xA0}

func TestUnwrapProvisioning_UnsignedRejectedWithOwnerKey(t *testing.T) {
	// Model 1 strict: unsigned BMO with an Owner key but no delegate authority.
	// This MUST be rejected.
	owner := genECKey(t)
	bmo := &BMO{OwnerPublicKey: owner.Public()}
	ctx := context.Background()

	_, _, err := bmo.unwrapProvisioning(ctx, bytes.NewReader(unsignedCBOR), BMOContentTypeImageBegin)
	if err == nil {
		t.Fatal("expected unsigned BMO to be rejected when Owner key is present")
	}
	if !strings.Contains(err.Error(), "unsigned") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUnwrapProvisioning_UnsignedAcceptedWithDelegateProvision(t *testing.T) {
	// Model 2: unsigned BMO with an Owner key AND delegate provision authority.
	// This MUST be accepted.
	owner := genECKey(t)
	bmo := &BMO{OwnerPublicKey: owner.Public()}
	ctx := fdo.WithPeerAuthority(context.Background(), fdo.PeerDelegateProvision)

	inner, signed, err := bmo.unwrapProvisioning(ctx, bytes.NewReader(unsignedCBOR), BMOContentTypeImageBegin)
	if err != nil {
		t.Fatalf("expected unsigned BMO to be accepted with delegate provision authority: %v", err)
	}
	if signed {
		t.Fatal("unsigned message should not be reported as signed")
	}
	if !bytes.Equal(inner, unsignedCBOR) {
		t.Fatal("inner payload should match raw input")
	}
}

func TestUnwrapProvisioning_UnsignedRejectedWithoutProvisionPerm(t *testing.T) {
	// A delegate exists but does NOT have provision authority.
	// Unsigned BMO MUST still be rejected.
	owner := genECKey(t)
	bmo := &BMO{OwnerPublicKey: owner.Public()}
	ctx := fdo.WithPeerAuthority(context.Background(), fdo.PeerDelegateOnboardOnly)

	_, _, err := bmo.unwrapProvisioning(ctx, bytes.NewReader(unsignedCBOR), BMOContentTypeImageBegin)
	if err == nil {
		t.Fatal("expected unsigned BMO to be rejected when delegate lacks provision authority")
	}
}

// Model 1: the Owner itself is the TO2 peer. Unsigned MUST be accepted —
// channel authority is REQUIRED and enabled by default. (Previously this was
// rejected whenever an Owner key was known, because a single bool could not
// distinguish "Owner-direct" from "onboard-only delegate".)
func TestUnwrapProvisioning_UnsignedAcceptedOwnerDirect(t *testing.T) {
	owner := genECKey(t)
	bmo := &BMO{OwnerPublicKey: owner.Public()}
	ctx := fdo.WithPeerAuthority(context.Background(), fdo.PeerOwnerDirect)

	inner, signed, err := bmo.unwrapProvisioning(ctx, bytes.NewReader(unsignedCBOR), BMOContentTypeImageBegin)
	if err != nil {
		t.Fatalf("expected unsigned BMO from Owner-direct peer to be accepted: %v", err)
	}
	if signed || !bytes.Equal(inner, unsignedCBOR) {
		t.Fatal("unexpected signed flag or inner payload")
	}
}

// Onboard-only delegate: unsigned MUST be rejected, for both gated messages,
// even though the Owner key is known. This is the H4 case.
func TestUnwrapProvisioning_UnsignedRejectedOnboardOnlyDelegate(t *testing.T) {
	owner := genECKey(t)
	bmo := &BMO{OwnerPublicKey: owner.Public()}
	ctx := fdo.WithPeerAuthority(context.Background(), fdo.PeerDelegateOnboardOnly)

	for _, ct := range []string{BMOContentTypeImageBegin, BMOContentTypeSet} {
		if _, _, err := bmo.unwrapProvisioning(ctx, bytes.NewReader(unsignedCBOR), ct); err == nil {
			t.Fatalf("%s: expected unsigned message from onboard-only delegate to be rejected", ct)
		}
	}
}

// Onboard-only delegate relaying an Owner-signed artifact: MUST be accepted.
// This is the relay path delegation exists for.
func TestUnwrapProvisioning_OnboardOnlyDelegateRelaysOwnerSigned(t *testing.T) {
	owner := genECKey(t)
	signer := &OwnerSigner{Key: owner}
	payload := []byte{0xA1, 0x01, 0x02}
	signedMsg, err := signer.Sign(payload, BMOContentTypeImageBegin)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	bmo := &BMO{OwnerPublicKey: owner.Public()}
	ctx := fdo.WithPeerAuthority(context.Background(), fdo.PeerDelegateOnboardOnly)

	inner, signed, err := bmo.unwrapProvisioning(ctx, bytes.NewReader(signedMsg), BMOContentTypeImageBegin)
	if err != nil {
		t.Fatalf("expected Owner-signed artifact relayed by onboard-only delegate to be accepted: %v", err)
	}
	if !signed || !bytes.Equal(inner, payload) {
		t.Fatal("unexpected signed flag or inner payload")
	}
}

// Same bytes, only the peer varies: proves each decision is attributable to
// the peer authority.
func TestUnsignedProvisioningAllowed_Matrix(t *testing.T) {
	cases := []struct {
		peer     fdo.PeerAuthority
		ownerKey bool
		want     bool
	}{
		{fdo.PeerOwnerDirect, true, true},
		{fdo.PeerDelegateProvision, true, true},
		{fdo.PeerDelegateOnboardOnly, true, false},
		{fdo.PeerUnknown, true, false},
		{fdo.PeerUnknown, false, true},
	}
	for _, c := range cases {
		if got, _ := unsignedProvisioningAllowed(c.peer, c.ownerKey); got != c.want {
			t.Errorf("peer=%s ownerKey=%v: got %v, want %v", c.peer, c.ownerKey, got, c.want)
		}
		if c.ownerKey && c.peer != fdo.PeerUnknown && c.want != c.peer.HasProvisionAuthority() {
			t.Errorf("peer=%s: HasProvisionAuthority disagrees with decision", c.peer)
		}
	}
}

func TestUnwrapProvisioning_UnsignedAcceptedWithNoOwnerKey(t *testing.T) {
	// Legacy/test: no Owner key at all — unsigned is always accepted.
	bmo := &BMO{}
	ctx := context.Background()

	inner, signed, err := bmo.unwrapProvisioning(ctx, bytes.NewReader(unsignedCBOR), BMOContentTypeImageBegin)
	if err != nil {
		t.Fatalf("expected unsigned BMO to be accepted with no Owner key: %v", err)
	}
	if signed {
		t.Fatal("unsigned message should not be reported as signed")
	}
	if !bytes.Equal(inner, unsignedCBOR) {
		t.Fatal("inner payload should match raw input")
	}
}

func TestUnwrapProvisioning_SignedAcceptedWithOwnerKey(t *testing.T) {
	// Model 3: Owner-signed COSE_Sign1. Verify it's accepted.
	owner := genECKey(t)
	signer := &OwnerSigner{Key: owner}
	payload := []byte{0xA1, 0x01, 0x02} // minimal CBOR map {1: 2}
	signedMsg, err := signer.Sign(payload, BMOContentTypeImageBegin)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	bmo := &BMO{OwnerPublicKey: owner.Public()}
	ctx := context.Background()

	inner, wasSigned, err := bmo.unwrapProvisioning(ctx, bytes.NewReader(signedMsg), BMOContentTypeImageBegin)
	if err != nil {
		t.Fatalf("expected signed BMO to be accepted: %v", err)
	}
	if !wasSigned {
		t.Fatal("signed message should be reported as signed")
	}
	if !bytes.Equal(inner, payload) {
		t.Fatalf("payload mismatch: got %x, want %x", inner, payload)
	}
}

func TestUnwrapProvisioning_SignedRejectedWithWrongKey(t *testing.T) {
	// Sign with one key, verify with a different Owner key — must reject.
	signer := &OwnerSigner{Key: genECKey(t)}
	signedMsg, _ := signer.Sign([]byte{0xA0}, BMOContentTypeImageBegin)

	wrongOwner := genECKey(t)
	bmo := &BMO{OwnerPublicKey: wrongOwner.Public()}
	ctx := context.Background()

	_, _, err := bmo.unwrapProvisioning(ctx, bytes.NewReader(signedMsg), BMOContentTypeImageBegin)
	if err == nil {
		t.Fatal("expected signed BMO to be rejected with wrong Owner key")
	}
}
