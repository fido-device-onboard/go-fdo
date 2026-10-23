// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"io"
	"testing"

	fdo "github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/fsim/chunking"
)

// payload-begin is authorization-gated (fdo.payload.md, chunking-strategy.md
// "Authorization of Begin Messages"). These tests exercise
// Payload.authorizeBegin, the path Receive uses for "payload-begin".

var payloadData = []byte("#!/bin/sh\necho configured\n")

func payloadBegin(t *testing.T, mime string, withHash bool) []byte {
	t.Helper()
	b := chunking.BeginMessage{HashAlg: "sha256", FSIMFields: map[int]any{-1: mime}}
	if withHash {
		h := sha256.Sum256(payloadData)
		b.ExpectedHash = h[:]
	}
	data, err := b.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func peerCtx(p fdo.PeerAuthority) context.Context {
	return fdo.WithPeerAuthority(context.Background(), p)
}

func authCode(err error) int { return chunking.ErrorCode(err, -1) }

func TestPayloadAuth_UnsignedPeerMatrix(t *testing.T) {
	owner := genECKey(t)
	body := payloadBegin(t, "application/x-sh", true)
	cases := []struct {
		peer fdo.PeerAuthority
		ok   bool
	}{
		{fdo.PeerOwnerDirect, true},
		{fdo.PeerDelegateProvision, true},
		{fdo.PeerDelegateOnboardOnly, false},
		{fdo.PeerUnknown, false}, // Owner key known but no peer recorded: fail closed
	}
	for _, c := range cases {
		p := &Payload{OwnerPublicKey: owner.Public()}
		_, err := p.authorizeBegin(peerCtx(c.peer), bytes.NewReader(body))
		if (err == nil) != c.ok {
			t.Errorf("peer=%s: accepted=%v, want %v (%v)", c.peer, err == nil, c.ok, err)
		}
		if !c.ok && authCode(err) != chunking.CodeNotAuthorized {
			t.Errorf("peer=%s: code %d, want 15", c.peer, authCode(err))
		}
	}
}

// The documented local policy: listed MIME types are accepted unsigned even
// from an onboard-only peer; anything else is still refused.
func TestPayloadAuth_UnauthorizedMIMETypesPolicy(t *testing.T) {
	owner := genECKey(t)
	p := &Payload{OwnerPublicKey: owner.Public(), UnauthorizedMIMETypes: []string{"application/x-timezone"}}
	ctx := peerCtx(fdo.PeerDelegateOnboardOnly)

	if _, err := p.authorizeBegin(ctx, bytes.NewReader(payloadBegin(t, "application/x-timezone", true))); err != nil {
		t.Errorf("allowlisted MIME type should be accepted: %v", err)
	}
	if _, err := p.authorizeBegin(ctx, bytes.NewReader(payloadBegin(t, "application/x-sh", true))); authCode(err) != chunking.CodeNotAuthorized {
		t.Errorf("non-allowlisted MIME type from onboard-only peer must be refused, got %v", err)
	}
}

// The relay path: an Owner-signed payload-begin delivered by an onboard-only
// peer is accepted.
func TestPayloadAuth_OwnerSignedRelayedByOnboardOnly(t *testing.T) {
	owner := genECKey(t)
	signed, err := (&OwnerSigner{Key: owner}).SignArtifact(payloadBegin(t, "application/x-sh", true),
		PayloadContentTypeBegin, cose.AADPayloadProvision)
	if err != nil {
		t.Fatal(err)
	}
	p := &Payload{OwnerPublicKey: owner.Public()}
	inner, err := p.authorizeBegin(peerCtx(fdo.PeerDelegateOnboardOnly), bytes.NewReader(signed))
	if err != nil {
		t.Fatalf("Owner-signed payload-begin should be accepted from any peer: %v", err)
	}
	var b chunking.BeginMessage
	if err := b.UnmarshalCBOR(inner); err != nil || b.FSIMFields[-1] != "application/x-sh" {
		t.Errorf("inner begin not returned: %v %+v", err, b)
	}
}

func TestPayloadAuth_SignedNegatives(t *testing.T) {
	owner := genECKey(t)
	begin := payloadBegin(t, "application/x-sh", true)
	sign := func(ct string, aad []byte, body []byte) []byte {
		s, err := (&OwnerSigner{Key: owner}).SignArtifact(body, ct, aad)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	tampered := sign(PayloadContentTypeBegin, cose.AADPayloadProvision, begin)
	tampered[len(tampered)-3] ^= 0x01

	cases := map[string][]byte{
		"BMO content type":                     sign(BMOContentTypeImageBegin, cose.AADPayloadProvision, begin),
		"BMO external AAD (domain separation)": sign(PayloadContentTypeBegin, cose.AADBmoProvision, begin),
		"tampered signature":                   tampered,
		"signed inline begin without hash":     sign(PayloadContentTypeBegin, cose.AADPayloadProvision, payloadBegin(t, "application/x-sh", false)),
	}
	for name, body := range cases {
		p := &Payload{OwnerPublicKey: owner.Public()}
		// Even an Owner-direct peer: a signed message is judged on its
		// signature alone, never downgraded to channel authority.
		if _, err := p.authorizeBegin(peerCtx(fdo.PeerOwnerDirect), bytes.NewReader(body)); authCode(err) != chunking.CodeNotAuthorized {
			t.Errorf("%s: expected rejection with 15, got %v", name, err)
		}
	}
}

func TestPayloadAuth_DelegateSigned(t *testing.T) {
	owner, leaf := genECKey(t), genECKey(t)
	chainFor := func(perms ...asn1.ObjectIdentifier) []*x509.Certificate {
		c, err := fdo.GenerateDelegate(owner, fdo.DelegateFlagLeaf, leaf.Public(), "Delegate", "Owner", perms, x509.ECDSAWithSHA256)
		if err != nil {
			t.Fatal(err)
		}
		return []*x509.Certificate{c}
	}
	begin := payloadBegin(t, "application/x-sh", true)
	p := &Payload{OwnerPublicKey: owner.Public()}
	ctx := peerCtx(fdo.PeerDelegateOnboardOnly)

	ok, err := (&DelegateSigner{Key: leaf, Chain: chainFor(fdo.OIDPermitProvision)}).SignArtifact(begin, PayloadContentTypeBegin, cose.AADPayloadProvision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.authorizeBegin(ctx, bytes.NewReader(ok)); err != nil {
		t.Errorf("PERM.7 delegate-signed payload-begin should be accepted: %v", err)
	}

	// DelegateSigner refuses a chain without PERM.7, so build it directly to
	// prove the device refuses it too.
	noPerm, err := signProvisioningArtifact(begin, PayloadContentTypeBegin, cose.AADPayloadProvision, nil, leaf, chainFor(fdo.OIDPermitOnboardNewCred))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.authorizeBegin(ctx, bytes.NewReader(noPerm)); authCode(err) != chunking.CodeNotAuthorized {
		t.Errorf("delegate without PERM.7 must be refused with 15, got %v", err)
	}
}

// Inline content must match expected_hash in the authorizing payload-begin,
// in both unified and streaming modes.
func TestPayloadInline_BeginHashEnforced(t *testing.T) {
	h := sha256.Sum256([]byte("something else"))
	begin := chunking.BeginMessage{HashAlg: "sha256", ExpectedHash: h[:], FSIMFields: map[int]any{-1: "application/x-sh"}}

	// Unified.
	handler := &stubPayloadHandler{}
	p := &Payload{UnifiedHandler: handler, buffer: bytes.NewBuffer(payloadData), begin: begin}
	if err := p.onEndUnified(context.Background())(chunking.EndMessage{}); authCode(err) != chunking.CodeHashMismatch {
		t.Errorf("unified: expected hash mismatch (11), got %v", err)
	}

	// Streaming: mismatch detected at end, payload cancelled.
	ch := &recordingChunkedHandler{}
	p = &Payload{ChunkedHandler: ch}
	if err := p.onBeginChunked(begin); err != nil {
		t.Fatal(err)
	}
	_ = p.onChunkChunked(payloadData)
	if err := p.onEndChunked(chunking.EndMessage{}); authCode(err) != chunking.CodeHashMismatch {
		t.Errorf("chunked: expected hash mismatch (11), got %v", err)
	}
	if !ch.cancelled || ch.ended {
		t.Errorf("chunked: payload must be cancelled, not finalized (cancelled=%v ended=%v)", ch.cancelled, ch.ended)
	}
}

// URL delivery without a hash, through a fetcher that cannot validate TLS,
// is refused (19) before anything is downloaded.
func TestPayloadURL_NoHashRefused(t *testing.T) {
	f := &mockURLFetcher{data: map[string][]byte{"https://cdn/p.sh": payloadData}}
	p := &Payload{UnifiedHandler: &stubPayloadHandler{}, URLFetcher: f, buffer: &bytes.Buffer{},
		begin: chunking.BeginMessage{DeliveryMode: DeliveryModeURL, URL: "https://cdn/p.sh", FSIMFields: map[int]any{-1: "application/x-sh"}}}
	if err := p.onEndUnified(context.Background())(chunking.EndMessage{}); authCode(err) != chunking.CodeUnauthenticatedSource {
		t.Errorf("expected 19, got %v", err)
	}
	if len(f.fetchedURLs) != 0 {
		t.Error("nothing should be downloaded")
	}
}

// Streaming handlers cannot do delivery by reference: rejected with 14.
func TestPayloadURL_ChunkedHandlerRejected(t *testing.T) {
	p := &Payload{ChunkedHandler: &recordingChunkedHandler{}}
	err := p.onBeginChunked(chunking.BeginMessage{DeliveryMode: DeliveryModeURL, URL: "https://cdn/p", FSIMFields: map[int]any{-1: "a"}})
	if authCode(err) != chunking.CodeDeliveryModeNotSupported {
		t.Errorf("expected 14, got %v", err)
	}
}

type recordingChunkedHandler struct{ cancelled, ended bool }

func (h *recordingChunkedHandler) SupportsMimeType(string) bool { return true }
func (h *recordingChunkedHandler) BeginPayload(string, string, uint64, map[string]any) error {
	return nil
}
func (h *recordingChunkedHandler) ReceiveChunk([]byte) error { return nil }
func (h *recordingChunkedHandler) EndPayload() (int, string, error) {
	h.ended = true
	return 0, "", nil
}
func (h *recordingChunkedHandler) CancelPayload() error {
	h.cancelled = true
	return nil
}

// Wiring: Receive must route payload-begin through authorization. An
// unsigned begin from an onboard-only peer produces an error message with
// code 15 and never reaches the handler.
func TestPayloadReceive_GatesPayloadBegin(t *testing.T) {
	owner := genECKey(t)
	handler := &stubPayloadHandler{}
	p := &Payload{UnifiedHandler: handler, OwnerPublicKey: owner.Public()}

	var sent []string
	var errBody bytes.Buffer
	respond := func(key string) io.Writer {
		sent = append(sent, key)
		if key == "error" {
			return &errBody
		}
		return io.Discard
	}
	ctx := peerCtx(fdo.PeerDelegateOnboardOnly)
	if err := p.Receive(ctx, "payload-begin", bytes.NewReader(payloadBegin(t, "application/x-sh", true)), respond, func() {}); err != nil {
		t.Fatal(err)
	}
	var errMsg map[int]any
	if len(sent) != 1 || sent[0] != "error" || cbor.Unmarshal(errBody.Bytes(), &errMsg) != nil {
		t.Fatalf("expected a single error message, got %v", sent)
	}
	if code, _ := errMsg[0].(int64); code != chunking.CodeNotAuthorized {
		t.Errorf("error code = %v, want 15", errMsg[0])
	}
	if p.receiver != nil {
		t.Error("an unauthorized payload-begin must not start a transfer")
	}

	// Control: the same begin from an Owner-direct peer starts a transfer.
	sent = nil
	if err := p.Receive(peerCtx(fdo.PeerOwnerDirect), "payload-begin", bytes.NewReader(payloadBegin(t, "application/x-sh", true)), respond, func() {}); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 0 || p.receiver == nil || !p.receiver.IsReceiving() {
		t.Errorf("Owner-direct payload-begin should start a transfer (sent=%v)", sent)
	}
}
