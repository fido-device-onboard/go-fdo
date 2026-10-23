// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package chunking_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"strings"
	"testing"
	"time"

	fdo "github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/fsim"
	"github.com/fido-device-onboard/go-fdo/fsim/chunking"
)

// ---------------------------------------------------------------------------
// Begin message keys 5..9 and legacy aliases
// ---------------------------------------------------------------------------

func TestBeginMessage_DeliveryKeysRoundTrip(t *testing.T) {
	in := chunking.BeginMessage{
		DeliveryMode: chunking.DeliveryModeMetaURL, URL: "https://x/m", TLSCA: []byte{1},
		ExpectedHash: []byte{2}, MetaSigner: []byte{3},
		FSIMFields: map[int]any{-1: "t"},
	}
	data, err := in.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	var raw map[int64]any
	if err := cbor.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, k := range []int64{5, 6, 7, 8, 9} {
		if _, ok := raw[k]; !ok {
			t.Errorf("generic key %d not emitted", k)
		}
	}
	for _, k := range []int64{-6, -7, -8, -9, -10} {
		if _, ok := raw[k]; ok {
			t.Errorf("legacy key %d must never be emitted", k)
		}
	}
	var out chunking.BeginMessage
	if err := out.UnmarshalCBOR(data); err != nil {
		t.Fatal(err)
	}
	if out.DeliveryMode != in.DeliveryMode || out.URL != in.URL || string(out.MetaSigner) != string(in.MetaSigner) {
		t.Errorf("round trip mismatch: %+v", out)
	}
}

// Older code that still sets a legacy alias in FSIMFields: the value is
// translated to the generic key (never emitted as the alias, never dropped),
// and a conflicting generic value is an error.
func TestBeginMessage_MarshalTranslatesLegacyFSIMFields(t *testing.T) {
	b := chunking.BeginMessage{FSIMFields: map[int]any{-1: "t", -9: []byte{9}}}
	data, err := b.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	var raw map[int64]any
	_ = cbor.Unmarshal(data, &raw)
	if _, ok := raw[-9]; ok {
		t.Error("legacy alias -9 must not be emitted")
	}
	if h, _ := raw[8].([]byte); len(h) != 1 || h[0] != 9 {
		t.Errorf("legacy -9 value should be emitted as key 8, got %v", raw[8])
	}
	conflict := chunking.BeginMessage{ExpectedHash: []byte{1}, FSIMFields: map[int]any{-9: []byte{2}}}
	if _, err := conflict.MarshalCBOR(); err == nil {
		t.Error("conflicting generic and legacy values must be an error")
	}
}

func TestBeginMessage_LegacyAliasesAccepted(t *testing.T) {
	data, _ := cbor.Marshal(map[int]any{-1: "t", -6: uint64(1), -7: "https://x/i", -9: []byte{7}})
	var b chunking.BeginMessage
	if err := b.UnmarshalCBOR(data); err != nil {
		t.Fatal(err)
	}
	if b.DeliveryMode != chunking.DeliveryModeURL || b.URL != "https://x/i" || len(b.ExpectedHash) != 1 {
		t.Errorf("legacy aliases not folded into generic fields: %+v", b)
	}
}

func TestBeginMessage_AliasConflictRejected(t *testing.T) {
	data, _ := cbor.Marshal(map[int]any{6: "https://a", -7: "https://b"})
	var b chunking.BeginMessage
	if err := b.UnmarshalCBOR(data); err == nil {
		t.Fatal("generic key and legacy alias with different values must be rejected")
	}
	same, _ := cbor.Marshal(map[int]any{6: "https://a", -7: "https://a"})
	if err := b.UnmarshalCBOR(same); err != nil {
		t.Fatalf("identical values should be accepted: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Fetchers
// ---------------------------------------------------------------------------

type fetcher struct {
	data    map[string][]byte
	fetched []string
}

func (f *fetcher) Fetch(url string, _ []byte) ([]byte, error) {
	f.fetched = append(f.fetched, url)
	d, ok := f.data[url]
	if !ok {
		return nil, errors.New("not found")
	}
	return d, nil
}

// validatingFetcher reports every https fetch as TLS-validated.
type validatingFetcher struct{ fetcher }

func (f *validatingFetcher) FetchValidated(url string, ca []byte) ([]byte, bool, error) {
	d, err := f.Fetch(url, ca)
	return d, strings.HasPrefix(url, "https://"), err
}

func code(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	return chunking.ErrorCode(err, -1)
}

const metaURL = "https://vendor.example/meta.cbor"
const imageURL = "https://cdn.example/image.bin"

var image = []byte("the image")

func imageHash() []byte { h := sha256.Sum256(image); return h[:] }

func metaBytes(t *testing.T, m chunking.MetaPayload) []byte {
	t.Helper()
	b, err := m.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func genKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func delegateChain(t *testing.T, owner *ecdsa.PrivateKey, leaf *ecdsa.PrivateKey, perms ...asn1.ObjectIdentifier) []*x509.Certificate {
	t.Helper()
	c, err := fdo.GenerateDelegate(owner, fdo.DelegateFlagLeaf, leaf.Public(), "Delegate", "Owner", perms, x509.ECDSAWithSHA256)
	if err != nil {
		t.Fatal(err)
	}
	return []*x509.Certificate{c}
}

// ---------------------------------------------------------------------------
// Resolve: URL mode
// ---------------------------------------------------------------------------

func TestResolve_URLMode(t *testing.T) {
	plain := func() *fetcher { return &fetcher{data: map[string][]byte{imageURL: image}} }
	valid := func() *validatingFetcher { return &validatingFetcher{*plain()} }

	cases := []struct {
		name  string
		f     chunking.URLFetcher
		url   string
		hash  []byte
		want  int
		fetch bool
	}{
		{"hash pins content", plain(), imageURL, imageHash(), 0, true},
		{"wrong hash", plain(), imageURL, make([]byte, 32), chunking.CodeHashMismatch, true},
		{"no hash, cannot validate TLS: refused before fetch", plain(), imageURL, nil, chunking.CodeUnauthenticatedSource, false},
		{"no hash, validated TLS", valid(), imageURL, nil, 0, true},
		{"no hash, http is never validated", valid(), "http://cdn.example/image.bin", nil, chunking.CodeUnauthenticatedSource, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if vf, ok := c.f.(*validatingFetcher); ok && c.url != imageURL {
				vf.data[c.url] = image
			}
			b := chunking.BeginMessage{DeliveryMode: chunking.DeliveryModeURL, URL: c.url, ExpectedHash: c.hash, HashAlg: "sha256"}
			_, err := chunking.Resolve(c.f, b, nil)
			if got := code(t, err); got != c.want {
				t.Errorf("code = %d, want %d (%v)", got, c.want, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Resolve: meta-URL mode
// ---------------------------------------------------------------------------

func TestResolve_MetaSignedByOwner(t *testing.T) {
	owner := genKey(t)
	signed, err := fsim.SignMetaPayload(metaBytes(t, chunking.MetaPayload{
		MIMEType: "application/efi", URL: imageURL, HashAlg: "sha256", ExpectedHash: imageHash(), BootArgs: "quiet",
	}), owner)
	if err != nil {
		t.Fatal(err)
	}
	f := &fetcher{data: map[string][]byte{metaURL: signed, imageURL: image}}
	res, err := chunking.Resolve(f, chunking.BeginMessage{DeliveryMode: chunking.DeliveryModeMetaURL, URL: metaURL}, owner.Public())
	if err != nil {
		t.Fatalf("Owner-signed meta-payload (no meta_signer) should verify against the Owner key: %v", err)
	}
	if !res.MetaAuthenticated || res.Meta.BootArgs != "quiet" {
		t.Errorf("unexpected result: %+v", res)
	}

	// Same meta-payload, different Owner key: rejected (12).
	_, err = chunking.Resolve(f, chunking.BeginMessage{DeliveryMode: chunking.DeliveryModeMetaURL, URL: metaURL}, genKey(t).Public())
	if got := code(t, err); got != chunking.CodeMetaSignatureInvalid {
		t.Errorf("wrong Owner key: code = %d, want 12", got)
	}
}

func TestResolve_MetaSignedByDelegateChain(t *testing.T) {
	owner, leaf := genKey(t), genKey(t)
	meta := metaBytes(t, chunking.MetaPayload{MIMEType: "application/efi", URL: imageURL, HashAlg: "sha256", ExpectedHash: imageHash()})
	begin := chunking.BeginMessage{DeliveryMode: chunking.DeliveryModeMetaURL, URL: metaURL}

	// PERM.7 delegate: accepted.
	signed, err := fsim.SignMetaPayloadWithChain(meta, leaf, delegateChain(t, owner, leaf, fdo.OIDPermitProvision))
	if err != nil {
		t.Fatal(err)
	}
	f := &fetcher{data: map[string][]byte{metaURL: signed, imageURL: image}}
	if _, err := chunking.Resolve(f, begin, owner.Public()); err != nil {
		t.Fatalf("PERM.7 delegate-signed meta-payload should be accepted: %v", err)
	}

	// Delegate without PERM.7: the signer refuses, so hand-build the
	// artifact to prove the device refuses too (12).
	chain := delegateChain(t, owner, leaf, fdo.OIDPermitOnboardNewCred)
	var s1 cose.Sign1[[]byte, []byte]
	s1.Payload = cbor.NewByteWrap(meta)
	s1.Unprotected = cose.HeaderMap{cose.Label{Int64: 33}: [][]byte{chain[0].Raw}}
	if err := s1.Sign(leaf, nil, cose.AADMetaPayload, nil); err != nil {
		t.Fatal(err)
	}
	noPerm, _ := s1.Tag().MarshalCBOR()
	f.data[metaURL] = noPerm
	_, err = chunking.Resolve(f, begin, owner.Public())
	if got := code(t, err); got != chunking.CodeMetaSignatureInvalid {
		t.Errorf("delegate without PERM.7: code = %d, want 12 (%v)", got, err)
	}
	if _, err := fsim.SignMetaPayloadWithChain(meta, leaf, chain); err == nil {
		t.Error("SignMetaPayloadWithChain should refuse a chain without PERM.7")
	}
}

func TestResolve_MetaUnauthenticated(t *testing.T) {
	pointer := chunking.MetaPayload{MIMEType: "application/efi", URL: imageURL, HashAlg: "sha256", ExpectedHash: imageHash()}
	withInstr := pointer
	withInstr.BootArgs = "init=/bin/sh"
	withCA := pointer
	withCA.TLSCA = []byte{1}
	withFSIMKey := pointer
	withFSIMKey.Extra = map[int]any{-1: "x"}

	cases := []struct {
		name      string
		meta      chunking.MetaPayload
		beginHash []byte
		want      int
	}{
		{"no begin hash: nothing authenticates the image", pointer, nil, chunking.CodeUnauthenticatedSource},
		{"pointer only, begin hash pins image", pointer, imageHash(), 0},
		{"boot_args from unauthenticated meta", withInstr, imageHash(), chunking.CodeNotAuthorized},
		{"tls_ca from unauthenticated meta", withCA, imageHash(), chunking.CodeNotAuthorized},
		{"FSIM-defined key from unauthenticated meta", withFSIMKey, imageHash(), chunking.CodeNotAuthorized},
		{"meta hash disagrees with begin hash", chunking.MetaPayload{MIMEType: "a", URL: imageURL, ExpectedHash: make([]byte, 32)}, imageHash(), chunking.CodeHashMismatch},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fetcher{data: map[string][]byte{metaURL: metaBytes(t, c.meta), imageURL: image}}
			b := chunking.BeginMessage{DeliveryMode: chunking.DeliveryModeMetaURL, URL: metaURL, ExpectedHash: c.beginHash, HashAlg: "sha256"}
			_, err := chunking.Resolve(f, b, nil)
			if got := code(t, err); got != c.want {
				t.Errorf("code = %d, want %d (%v)", got, c.want, err)
			}
			if c.want == chunking.CodeUnauthenticatedSource && len(f.fetched) != 1 {
				t.Errorf("image must not be downloaded when it cannot be authenticated; fetched %v", f.fetched)
			}
		})
	}
}

// An unsigned meta-payload fetched over validated TLS is authenticated: its
// hash counts as evidence and its instruction fields may be used.
func TestResolve_MetaOverValidatedTLS(t *testing.T) {
	meta := chunking.MetaPayload{MIMEType: "application/efi", URL: imageURL, HashAlg: "sha256", ExpectedHash: imageHash(), BootArgs: "quiet"}
	f := &validatingFetcher{fetcher{data: map[string][]byte{metaURL: metaBytes(t, meta), imageURL: image}}}
	res, err := chunking.Resolve(f, chunking.BeginMessage{DeliveryMode: chunking.DeliveryModeMetaURL, URL: metaURL}, nil)
	if err != nil {
		t.Fatalf("meta over validated TLS should be accepted: %v", err)
	}
	if !res.MetaAuthenticated || res.Meta.BootArgs != "quiet" {
		t.Errorf("unexpected result: %+v", res)
	}
}

// ---------------------------------------------------------------------------
// VerifyArtifact: scope
// ---------------------------------------------------------------------------

var testAAD = cose.AADBmoProvision

const testCT = "application/cbor+fdo.test"

func artifact(t *testing.T, key *ecdsa.PrivateKey, protected cose.HeaderMap) []byte {
	t.Helper()
	var s1 cose.Sign1[[]byte, []byte]
	s1.Payload = cbor.NewByteWrap([]byte{0xA0})
	s1.Protected = cose.HeaderMap{cose.Label{Int64: 3}: testCT}
	for k, v := range protected {
		s1.Protected[k] = v
	}
	if err := s1.Sign(key, nil, testAAD, nil); err != nil {
		t.Fatal(err)
	}
	b, err := s1.Tag().MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifyArtifact_Scope(t *testing.T) {
	owner := genKey(t)
	guid := []byte("0123456789abcdef")
	const nowSec = uint64(2_000_000_000)
	now := time.Unix(int64(nowSec), 0)
	sc := chunking.ScopeContext{DeviceGUID: guid, Now: func() time.Time { return now }}
	scope := func(m map[string]any) cose.HeaderMap { return cose.HeaderMap{chunking.ScopeLabel: m} }

	cases := []struct {
		name string
		hdr  cose.HeaderMap
		sc   chunking.ScopeContext
		want int
	}{
		{"no scope", nil, sc, 0},
		{"guid matches", scope(map[string]any{"guid": guid}), sc, 0},
		{"guid in array", scope(map[string]any{"guid": [][]byte{[]byte("other-guid-xxxxx"), guid}}), sc, 0},
		{"guid mismatch", scope(map[string]any{"guid": []byte("another-device!!")}), sc, chunking.CodeScopeMismatch},
		{"guid but device GUID unknown", scope(map[string]any{"guid": guid}), chunking.ScopeContext{Now: sc.Now}, chunking.CodeNotAuthorized},
		{"within window", scope(map[string]any{"not_before": nowSec - 10, "not_after": nowSec + 10}), sc, 0},
		{"expired", scope(map[string]any{"not_after": nowSec - 1}), sc, chunking.CodeValidityFailed},
		{"no trusted clock", scope(map[string]any{"not_after": nowSec + 10}), chunking.ScopeContext{DeviceGUID: guid}, chunking.CodeValidityFailed},
		{"generation without rollback storage", scope(map[string]any{"generation": uint64(3)}), sc, chunking.CodeSuperseded},
		{"unknown field", scope(map[string]any{"color": "red"}), sc, chunking.CodeNotAuthorized},
		{"legacy label accepted", cose.HeaderMap{chunking.LegacyBmoScopeLabel: map[string]any{"guid": guid}}, sc, 0},
		{"both labels rejected", cose.HeaderMap{chunking.ScopeLabel: map[string]any{}, chunking.LegacyBmoScopeLabel: map[string]any{}}, sc, chunking.CodeNotAuthorized},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := chunking.VerifyArtifact(artifact(t, owner, c.hdr), owner.Public(), testCT, testAAD, c.sc)
			if got := code(t, err); got != c.want {
				t.Errorf("code = %d, want %d (%v)", got, c.want, err)
			}
		})
	}
}

func TestVerifyArtifact_SignerAndContentType(t *testing.T) {
	owner := genKey(t)
	a := artifact(t, owner, nil)
	if _, err := chunking.VerifyArtifact(a, genKey(t).Public(), testCT, testAAD, chunking.ScopeContext{}); code(t, err) != chunking.CodeNotAuthorized {
		t.Errorf("wrong Owner key must be rejected with 15: %v", err)
	}
	if _, err := chunking.VerifyArtifact(a, owner.Public(), "application/other", testAAD, chunking.ScopeContext{}); code(t, err) != chunking.CodeNotAuthorized {
		t.Errorf("content_type mismatch must be rejected with 15: %v", err)
	}
	if _, err := chunking.VerifyArtifact(a, owner.Public(), testCT, cose.AADMetaPayload, chunking.ScopeContext{}); code(t, err) != chunking.CodeNotAuthorized {
		t.Errorf("wrong external AAD (domain separation) must be rejected with 15: %v", err)
	}
}
