// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"slices"
	"testing"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/kex"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

type noModules struct{}

func (noModules) Module(context.Context) (string, serviceinfo.OwnerModule, error) {
	return "", nil, ErrNotFound
}
func (noModules) NextModule(context.Context) (bool, error) { return false, nil }
func (noModules) CleanupModules(context.Context)           {}

// A TO2.DeviceSvcInfo20 that does not decode must produce an Error message,
// not an OwnerSvcInfo20 with an empty body.
func TestDeviceSvcInfo20DecodeErrorIsProtocolError(t *testing.T) {
	s := &TO2Server{Modules: noModules{}}
	respType, resp := s.Respond(context.Background(), protocol.TO2DeviceSvcInfo20MsgType, bytes.NewReader([]byte{0xff, 0x00}))
	if respType != protocol.ErrorMsgType {
		t.Fatalf("expected Error message (%d), got type %d (%v)", protocol.ErrorMsgType, respType, resp)
	}
	errMsg, ok := resp.(*protocol.ErrorMessage)
	if !ok {
		t.Fatalf("expected *protocol.ErrorMessage, got %T", resp)
	}
	if errMsg.Code != protocol.MessageBodyErrCode {
		t.Errorf("expected MessageBodyErrCode (%d), got %d", protocol.MessageBodyErrCode, errMsg.Code)
	}
}

func TestKexSuitesFor20(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsa2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsa3072, _ := rsa.GenerateKey(rand.Reader, 3072)

	for _, tc := range []struct {
		name          string
		device, owner crypto.PublicKey
		want          []kex.Suite
	}{
		{"P-384 device, P-384 owner", p384.Public(), p384.Public(), []kex.Suite{kex.ECDH384Suite}},
		{"P-256 device, P-256 owner", p256.Public(), p256.Public(), []kex.Suite{kex.ECDH256Suite}},
		{"P-256 device, RSA2048 owner", p256.Public(), rsa2048.Public(), []kex.Suite{kex.DHKEXid14Suite}},
		{"P-384 device, RSA3072 owner", p384.Public(), rsa3072.Public(), []kex.Suite{kex.DHKEXid15Suite}},
		// kex.Suite.Valid accepts every suite for RSA devices; the owner
		// key must still decide
		{"RSA2048 device, RSA2048 owner", rsa2048.Public(), rsa2048.Public(), []kex.Suite{kex.DHKEXid14Suite}},
		{"RSA2048 device, P-384 owner", rsa2048.Public(), p384.Public(), []kex.Suite{kex.ECDH384Suite}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := kexSuitesFor20(tc.device, tc.owner)
			if !slices.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
			// ASYMKEX can never be used in the 2.0 device-proves-first flow
			for _, s := range []kex.Suite{kex.ASYMKEX2048Suite, kex.ASYMKEX3072Suite} {
				if validKex20(s, tc.device, tc.owner) {
					t.Errorf("%s must not be valid in FDO 2.0", s)
				}
			}
		})
	}
}

func TestSelectSuites20(t *testing.T) {
	offered := []kex.Suite{kex.ECDH384Suite, kex.ECDH256Suite}
	ciphers := []kex.CipherSuiteID{kex.A256GcmCipher, kex.A128GcmCipher}

	// Configured suites are used when offered
	s, c, err := selectSuites20(offered, ciphers, kex.ECDH256Suite, kex.A128GcmCipher)
	if err != nil || s != kex.ECDH256Suite || c != kex.A128GcmCipher {
		t.Errorf("preferred: got %s/%d/%v", s, c, err)
	}
	// Otherwise the first usable offered suite
	s, c, err = selectSuites20(offered, ciphers, kex.ASYMKEX2048Suite, kex.A192GcmCipher)
	if err != nil || s != kex.ECDH384Suite || c != kex.A256GcmCipher {
		t.Errorf("fallback: got %s/%d/%v", s, c, err)
	}
	// Suites that cannot be used in 2.0 (or are unknown) are skipped
	s, _, err = selectSuites20([]kex.Suite{kex.ASYMKEX2048Suite, "BOGUS", kex.DHKEXid14Suite}, ciphers, kex.ECDH384Suite, kex.A256GcmCipher)
	if err != nil || s != kex.DHKEXid14Suite {
		t.Errorf("skip unusable: got %s/%v", s, err)
	}
	// Nothing usable is an error (not a nil session)
	if _, _, err := selectSuites20([]kex.Suite{kex.ASYMKEX2048Suite, "BOGUS"}, ciphers, kex.ECDH384Suite, kex.A256GcmCipher); err == nil {
		t.Error("expected an error when no offered key exchange suite is usable")
	}
	if _, _, err := selectSuites20(offered, []kex.CipherSuiteID{12345}, kex.ECDH384Suite, kex.A256GcmCipher); err == nil {
		t.Error("expected an error when no offered cipher suite is usable")
	}
}

func TestSelectHashType20(t *testing.T) {
	if alg, ok := selectHashType20([]protocol.HashAlg{protocol.HmacSha256Hash, protocol.Sha384Hash, protocol.Sha256Hash}); !ok || alg != protocol.Sha384Hash {
		t.Errorf("got %v/%v, want SHA384", alg, ok)
	}
	if _, ok := selectHashType20([]protocol.HashAlg{protocol.HmacSha256Hash, 99}); ok {
		t.Error("expected no supported hash type")
	}
}

// signTo1d signs a to1d (optionally carrying a delegate chain in the FDO 2.0
// payload) and round-trips it as on the wire.
func signTo1d(t *testing.T, signer crypto.Signer, chain []*x509.Certificate, aad []byte) *cose.Sign1[protocol.To1d, []byte] {
	t.Helper()
	payload := protocol.To1d{
		RV:       []protocol.RvTO2Addr{{DNSAddress: ptrTo("owner.example.com"), Port: 8080, TransportProtocol: protocol.HTTPTransport}},
		To0dHash: protocol.Hash{Algorithm: protocol.Sha256Hash, Value: make([]byte, 32)},
	}
	if chain != nil {
		certs := make([]*cbor.X509Certificate, len(chain))
		for i, c := range chain {
			certs[i] = (*cbor.X509Certificate)(c)
		}
		payload.DelegateChain = cbor.NewBstr(&certs)
	}
	s1 := cose.Sign1[protocol.To1d, []byte]{Payload: cbor.NewByteWrap(payload)}
	if err := s1.Sign(signer, nil, aad, nil); err != nil {
		t.Fatal(err)
	}
	b, err := cbor.Marshal(s1.Tag())
	if err != nil {
		t.Fatal(err)
	}
	var out cose.Sign1Tag[protocol.To1d, []byte]
	if err := cbor.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out.Untag()
}

func ptrTo[T any](v T) *T { return &v }

func TestVerifyTo1d(t *testing.T) {
	owner, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	delegate, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ownerPub := owner.Public()

	leaf := func(perms ...asn1.ObjectIdentifier) []*x509.Certificate {
		cert, err := GenerateDelegate(owner, DelegateFlagLeaf, delegate.Public(), "Delegate", "Owner", perms, x509.ECDSAWithSHA256)
		if err != nil {
			t.Fatal(err)
		}
		return []*x509.Certificate{cert}
	}

	for _, tc := range []struct {
		name    string
		to1d    *cose.Sign1[protocol.To1d, []byte]
		version uint16
		ok      bool
	}{
		{"owner signed, 2.0 voucher", signTo1d(t, owner, nil, cose.AADOwnerSign), 200, true},
		{"owner signed, 1.1 voucher", signTo1d(t, owner, nil, nil), 101, true},
		{"wrong key", signTo1d(t, other, nil, cose.AADOwnerSign), 200, false},
		{"2.0 voucher signed without AAD", signTo1d(t, owner, nil, nil), 200, false},
		{"1.1 voucher signed with AAD", signTo1d(t, owner, nil, cose.AADOwnerSign), 101, false},
		{"delegate with redirect", signTo1d(t, delegate, leaf(OIDPermitRedirect), cose.AADOwnerSign), 200, true},
		{"delegate without redirect", signTo1d(t, delegate, leaf(OIDPermitOnboardNewCred), cose.AADOwnerSign), 200, false},
		{"delegate chain, signed by owner key", signTo1d(t, owner, leaf(OIDPermitRedirect), cose.AADOwnerSign), 200, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyTo1d(tc.to1d, ownerPub, tc.version)
			if tc.ok && err != nil {
				t.Errorf("expected success, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Error("SECURITY FAILURE: expected verification to fail")
			}
		})
	}
}

type staticDelegateKeys map[string][]*x509.Certificate

func (d staticDelegateKeys) DelegateKey(name string) (crypto.Signer, []*x509.Certificate, error) {
	chain, ok := d[name]
	if !ok {
		return nil, nil, ErrNotFound
	}
	return nil, chain, nil
}

func TestCheckOnboardDelegateDisposition(t *testing.T) {
	owner, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	delegate, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	chain := func(perms ...asn1.ObjectIdentifier) []*x509.Certificate {
		cert, err := GenerateDelegate(owner, DelegateFlagLeaf, delegate.Public(), "Delegate", "Owner", perms, x509.ECDSAWithSHA384)
		if err != nil {
			t.Fatal(err)
		}
		return []*x509.Certificate{cert}
	}
	keys := staticDelegateKeys{
		"newOnly":   chain(OIDPermitOnboardNewCred),
		"reuseOnly": chain(OIDPermitOnboardReuseCred),
		"both":      chain(OIDPermitOnboardNewCred, OIDPermitOnboardReuseCred),
	}
	for _, tc := range []struct {
		delegate string
		reuse    bool
		ok       bool
	}{
		{"", true, true}, {"", false, true}, // no delegate: Owner onboards
		{"newOnly", false, true}, {"newOnly", true, false},
		{"reuseOnly", true, true}, {"reuseOnly", false, false},
		{"both", true, true}, {"both", false, true},
		{"missing", true, false},
	} {
		s := &TO2Server{DelegateKeys: keys, OnboardDelegate: tc.delegate}
		err := s.checkOnboardDelegateDisposition(protocol.Secp384r1KeyType, tc.reuse)
		if tc.ok != (err == nil) {
			t.Errorf("delegate %q reuse=%v: ok=%v, err=%v", tc.delegate, tc.reuse, tc.ok, err)
		}
	}
}

// VerifyDelegateChain must not write into the caller's slice (it appends a
// synthesized Owner root internally), and must work for RSA Owner keys.
func TestVerifyDelegateChainNoAliasingRSAOwner(t *testing.T) {
	owner, _ := rsa.GenerateKey(rand.Reader, 2048)
	delegate, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf, err := GenerateDelegate(owner, DelegateFlagLeaf, delegate.Public(), "Delegate", "Owner",
		[]asn1.ObjectIdentifier{OIDPermitRedirect}, x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := &x509.Certificate{}
	backing := []*x509.Certificate{leaf, sentinel}
	chain := backing[:1] // len 1, cap 2

	ownerPub := owner.Public()
	if err := VerifyDelegateChain(chain, &ownerPub, &OIDPermitRedirect); err != nil {
		t.Fatalf("valid chain rooted in an RSA Owner key rejected: %v", err)
	}
	if backing[1] != sentinel {
		t.Error("VerifyDelegateChain wrote into the caller's backing array")
	}
}

type errChecker struct{ err error }

func (c errChecker) CheckCertificate(*x509.Certificate) error { return c.err }

// The custom certificate checker hook is called directly (no reflection) and
// its error is classified as revocation or a custom check failure.
func TestCallCertificateChecker(t *testing.T) {
	saved := certificateChecker
	defer func() { certificateChecker = saved }()
	cert := &x509.Certificate{}

	certificateChecker = errChecker{nil}
	if err := callCertificateChecker(cert); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
	for msg, want := range map[string]CertificateValidationErrorCode{
		"certificate REVOKED by issuer": CertValidationErrorRevoked,
		"OCSP responder unreachable":    CertValidationErrorRevoked,
		"policy says no":                CertValidationErrorCustomCheck,
	} {
		certificateChecker = errChecker{errors.New(msg)}
		err := callCertificateChecker(cert)
		if err == nil || err.Code != want {
			t.Errorf("%q: got %v, want code %v", msg, err, want)
		}
	}
}

func TestLenientKex20(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsa2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	// The strict check rejects ECDH384 for P-256 keys; lenient accepts it
	if validKex20(kex.ECDH384Suite, p256.Public(), p256.Public()) {
		t.Error("strict check must reject ECDH384 for P-256 device and owner keys")
	}
	for _, tc := range []struct {
		suite kex.Suite
		owner crypto.PublicKey
		ok    bool
	}{
		{kex.ECDH384Suite, p256.Public(), true},
		{kex.ECDH256Suite, p256.Public(), true},
		{kex.DHKEXid15Suite, rsa2048.Public(), true},
		{kex.DHKEXid14Suite, p256.Public(), false}, // wrong family
		{kex.ECDH256Suite, rsa2048.Public(), false},
		{kex.ASYMKEX2048Suite, rsa2048.Public(), false}, // never in 2.0
	} {
		if got := lenientKex20(tc.suite, tc.owner); got != tc.ok {
			t.Errorf("lenientKex20(%s, %T) = %v, want %v", tc.suite, tc.owner, got, tc.ok)
		}
	}
}
