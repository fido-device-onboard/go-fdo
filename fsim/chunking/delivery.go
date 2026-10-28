// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package chunking

import (
	"crypto"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
)

// MetaPayload is the meta-payload used by meta-URL delivery
// (chunking-strategy.md "Meta-Payload"). Keys 0..127 are generic; key 5 is
// assigned to fdo.bmo (boot_args) for historical reasons; negative keys are
// FSIM-defined and kept in Extra.
type MetaPayload struct {
	MIMEType     string // 0, pointer
	URL          string // 1, pointer
	TLSCA        []byte // 2, instruction
	HashAlg      string // 3, constraint
	ExpectedHash []byte // 4, constraint
	BootArgs     string // 5, instruction (fdo.bmo: boot_args)
	Name         string // 6, informational
	Version      string // 7, informational
	Description  string // 8, informational

	// Extra holds any other keys (FSIM-defined negative keys, or generic
	// keys this implementation does not know). They are instruction-class
	// unless an FSIM explicitly classifies them otherwise.
	Extra map[int]any
}

// MarshalCBOR encodes MetaPayload to a CBOR map with integer keys.
func (m *MetaPayload) MarshalCBOR() ([]byte, error) {
	mp := make(map[int]any)
	for k, v := range m.Extra {
		mp[k] = v
	}
	mp[0] = m.MIMEType
	mp[1] = m.URL
	if len(m.TLSCA) > 0 {
		mp[2] = m.TLSCA
	}
	if m.HashAlg != "" {
		mp[3] = m.HashAlg
	}
	if len(m.ExpectedHash) > 0 {
		mp[4] = m.ExpectedHash
	}
	if m.BootArgs != "" {
		mp[5] = m.BootArgs
	}
	if m.Name != "" {
		mp[6] = m.Name
	}
	if m.Version != "" {
		mp[7] = m.Version
	}
	if m.Description != "" {
		mp[8] = m.Description
	}
	return cbor.Marshal(mp)
}

// UnmarshalCBOR decodes MetaPayload from a CBOR map.
func (m *MetaPayload) UnmarshalCBOR(data []byte) error {
	var raw map[any]any
	if err := cbor.Unmarshal(data, &raw); err != nil {
		return err
	}
	*m = MetaPayload{}
	for key, v := range raw {
		k, ok := intKey(key)
		if !ok {
			continue
		}
		switch k {
		case 0:
			m.MIMEType, _ = v.(string)
		case 1:
			m.URL, _ = v.(string)
		case 2:
			m.TLSCA, _ = v.([]byte)
		case 3:
			m.HashAlg, _ = v.(string)
		case 4:
			m.ExpectedHash, _ = v.([]byte)
		case 5:
			m.BootArgs, _ = v.(string)
		case 6:
			m.Name, _ = v.(string)
		case 7:
			m.Version, _ = v.(string)
		case 8:
			m.Description, _ = v.(string)
		default:
			if m.Extra == nil {
				m.Extra = make(map[int]any)
			}
			m.Extra[k] = v
		}
	}
	return nil
}

// InstructionFields lists the instruction-class fields present. From an
// unauthenticated meta-payload, any of these causes rejection (error 15):
// they change what the receiver trusts or does.
func (m *MetaPayload) InstructionFields() []string {
	var f []string
	if len(m.TLSCA) > 0 {
		f = append(f, "tls_ca")
	}
	if m.BootArgs != "" {
		f = append(f, "key 5 (boot_args)")
	}
	keys := make([]int, 0, len(m.Extra))
	for k := range m.Extra {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	for _, k := range keys {
		f = append(f, fmt.Sprintf("key %d", k))
	}
	return f
}

// URLFetcher fetches content by URL. If tlsCA is non-nil it is the TLS
// trust anchor to use.
type URLFetcher interface {
	Fetch(url string, tlsCA []byte) ([]byte, error)
}

// ValidatingFetcher is a URLFetcher that can report whether a fetch was made
// over TLS whose server certificate it actually validated (chain to tlsCA or
// a trusted system store, and host name match). Only such a fetch counts as
// evidence under "Authenticating Fetched Content". Fetchers that do not
// implement this interface never provide TLS evidence.
type ValidatingFetcher interface {
	URLFetcher
	FetchValidated(url string, tlsCA []byte) (data []byte, tlsValidated bool, err error)
}

// canValidateTLS reports whether a fetch of rawURL with f could be TLS
// evidence, so the decision can be made before downloading.
func canValidateTLS(f URLFetcher, rawURL string) bool {
	if _, ok := f.(ValidatingFetcher); !ok {
		return false
	}
	u, err := url.Parse(rawURL)
	return err == nil && strings.EqualFold(u.Scheme, "https")
}

func fetch(f URLFetcher, rawURL string, tlsCA []byte) ([]byte, bool, error) {
	if vf, ok := f.(ValidatingFetcher); ok {
		data, validated, err := vf.FetchValidated(rawURL, tlsCA)
		return data, validated && canValidateTLS(f, rawURL), err
	}
	data, err := f.Fetch(rawURL, tlsCA)
	return data, false, err
}

// VerifyMetaPayload authenticates a fetched meta-payload by signature
// (chunking-strategy.md "Meta-Payload Signing") and returns its inner CBOR.
//
//   - metaSigner present (begin key 9): the meta-payload MUST be signed and
//     MUST verify against that COSE_Key; any x5chain is ignored.
//   - metaSigner absent, signed: verified against the Owner key, or an
//     x5chain that validates to it and grants PERM.7.
//   - metaSigner absent, unsigned: returned as-is with signed=false.
//
// A signed meta-payload is never re-interpreted as unsigned. Errors carry
// code 12.
func VerifyMetaPayload(raw, metaSigner []byte, ownerKey crypto.PublicKey) (inner []byte, signed bool, err error) {
	if !IsSigned(raw) {
		if len(metaSigner) > 0 {
			return nil, false, transferErr(CodeMetaSignatureInvalid, "meta_signer named but meta-payload is not signed")
		}
		return raw, false, nil
	}
	var s1 cose.Sign1Tag[[]byte, []byte]
	if err := cbor.Unmarshal(raw, &s1); err != nil {
		return nil, true, transferErr(CodeMetaSignatureInvalid, "failed to parse signed meta-payload: %v", err)
	}

	var key crypto.PublicKey
	if len(metaSigner) > 0 {
		var ck cose.Key
		if err := cbor.Unmarshal(metaSigner, &ck); err != nil {
			return nil, true, transferErr(CodeMetaSignatureInvalid, "invalid meta_signer COSE_Key: %v", err)
		}
		if key, err = ck.Public(); err != nil {
			return nil, true, transferErr(CodeMetaSignatureInvalid, "invalid meta_signer COSE_Key: %v", err)
		}
	} else {
		if ownerKey == nil {
			return nil, true, transferErr(CodeMetaSignatureInvalid, "signed meta-payload without meta_signer, and no Owner key to verify it")
		}
		k, err := signerKey(s1.Unprotected, ownerKey)
		if err != nil {
			return nil, true, transferErr(CodeMetaSignatureInvalid, "meta-payload signer: %v", err)
		}
		key = k
	}

	valid, err := s1.Verify(key, nil, cose.AADMetaPayload)
	if err != nil || !valid {
		return nil, true, transferErr(CodeMetaSignatureInvalid, "meta-payload signature verification failed")
	}
	if s1.Payload == nil {
		return nil, true, transferErr(CodeMetaSignatureInvalid, "signed meta-payload has no payload")
	}
	return s1.Payload.Val, true, nil
}

// Resolved is the outcome of fetching content by reference.
type Resolved struct {
	Content []byte
	// Meta is the meta-payload (mode 2), or nil.
	Meta *MetaPayload
	// MetaAuthenticated is true when the meta-payload was authenticated by
	// signature or validated TLS. Only then may its instruction fields be
	// used; otherwise Resolve has already rejected any it carried.
	MetaAuthenticated bool
}

// Resolve fetches the content named by an authorized *-begin in delivery
// mode 1 or 2 and authenticates every fetched object per
// chunking-strategy.md "Authenticating Fetched Content":
//
//	evidence = a hash in an authorized parent, a signature (named
//	meta_signer, Owner, or PERM.7 x5chain), or TLS actually validated.
//
// No evidence ⇒ error 19. An unauthenticated meta-payload is only a pointer:
// it is rejected (15) if it carries instruction fields, and its hash fields
// are enforced but never count as evidence. Every hash present is enforced.
// The decision is made before downloading the content wherever possible.
func Resolve(f URLFetcher, begin BeginMessage, ownerKey crypto.PublicKey) (*Resolved, error) {
	if f == nil {
		return nil, transferErr(CodeDeliveryModeNotSupported, "no URL fetcher configured")
	}
	if begin.URL == "" {
		return nil, transferErr(CodeURLFetchFailed, "delivery mode %d requires url (key 6)", begin.DeliveryMode)
	}

	switch begin.DeliveryMode {
	case DeliveryModeURL:
		if len(begin.ExpectedHash) == 0 && !canValidateTLS(f, begin.URL) {
			return nil, transferErr(CodeUnauthenticatedSource,
				"URL delivery without expected_hash (key 8) requires TLS the device can validate; %s cannot be authenticated", begin.URL)
		}
		data, tlsOK, err := fetch(f, begin.URL, begin.TLSCA)
		if err != nil {
			return nil, transferErr(CodeURLFetchFailed, "fetch %s: %v", begin.URL, err)
		}
		if err := checkContent(data, tlsOK, hashReq{begin.HashAlg, begin.ExpectedHash, true}); err != nil {
			return nil, err
		}
		return &Resolved{Content: data}, nil

	case DeliveryModeMetaURL:
		return resolveMeta(f, begin, ownerKey)

	default:
		return nil, transferErr(CodeDeliveryModeNotSupported, "delivery mode %d not supported", begin.DeliveryMode)
	}
}

func resolveMeta(f URLFetcher, begin BeginMessage, ownerKey crypto.PublicKey) (*Resolved, error) {
	raw, metaTLS, err := fetch(f, begin.URL, begin.TLSCA)
	if err != nil {
		return nil, transferErr(CodeURLFetchFailed, "fetch meta-payload %s: %v", begin.URL, err)
	}
	inner, signed, err := VerifyMetaPayload(raw, begin.MetaSigner, ownerKey)
	if err != nil {
		return nil, err
	}
	var meta MetaPayload
	if err := meta.UnmarshalCBOR(inner); err != nil || meta.URL == "" || meta.MIMEType == "" {
		return nil, transferErr(CodeMetaParseError, "meta-payload malformed or missing mime_type/url")
	}

	metaAuth := signed || metaTLS
	if !metaAuth {
		if len(begin.ExpectedHash) == 0 {
			return nil, transferErr(CodeUnauthenticatedSource,
				"meta-payload is not signed, was not fetched over validated TLS, and image-begin pins no expected_hash (key 8)")
		}
		if instr := meta.InstructionFields(); len(instr) > 0 {
			return nil, transferErr(CodeNotAuthorized,
				"unauthenticated meta-payload carries instruction fields %v; it may only be used as a pointer", instr)
		}
		slog.Warn("meta-payload is unauthenticated; using it as a pointer only", "url", begin.URL)
	}

	// Content evidence, decided before downloading the content.
	metaHashIsEvidence := metaAuth && len(meta.ExpectedHash) > 0
	var contentCA []byte
	if metaAuth {
		contentCA = meta.TLSCA
	}
	if len(begin.ExpectedHash) == 0 && !metaHashIsEvidence && !canValidateTLS(f, meta.URL) {
		return nil, transferErr(CodeUnauthenticatedSource,
			"no hash pins the content and %s cannot be fetched over validated TLS", meta.URL)
	}

	data, contentTLS, err := fetch(f, meta.URL, contentCA)
	if err != nil {
		return nil, transferErr(CodeURLFetchFailed, "fetch content %s: %v", meta.URL, err)
	}
	if err := checkContent(data, contentTLS,
		hashReq{begin.HashAlg, begin.ExpectedHash, true},
		hashReq{meta.HashAlg, meta.ExpectedHash, metaAuth},
	); err != nil {
		return nil, err
	}
	return &Resolved{Content: data, Meta: &meta, MetaAuthenticated: metaAuth}, nil
}

// hashReq is a hash the fetched content must match. evidence reports whether
// a match also authenticates the content (false for a hash taken from an
// unauthenticated meta-payload: enforced, but proves nothing).
type hashReq struct {
	alg      string
	hash     []byte
	evidence bool
}

// checkContent enforces every present hash and requires at least one piece
// of evidence: an evidential hash, or validated TLS.
func checkContent(data []byte, tlsValidated bool, reqs ...hashReq) error {
	authenticated := tlsValidated
	for _, r := range reqs {
		if len(r.hash) == 0 {
			continue
		}
		alg := r.alg
		if alg == "" {
			alg = "sha256"
		}
		if err := VerifyHash(alg, data, r.hash); err != nil {
			return transferErr(CodeHashMismatch, "content hash verification failed: %v", err)
		}
		if r.evidence {
			authenticated = true
		}
	}
	if !authenticated {
		return transferErr(CodeUnauthenticatedSource, "fetched content is authenticated by no hash, signature, or validated TLS")
	}
	return nil
}
