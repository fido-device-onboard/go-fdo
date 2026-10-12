// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

func newTestKey(t *testing.T) (*ecdsa.PrivateKey, protocol.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := protocol.NewPublicKey(protocol.Secp256r1KeyType, &key.PublicKey, false)
	if err != nil {
		t.Fatal(err)
	}
	return key, *pub
}

// signSetupDevice20 signs and round-trips a SetupDevice20 as it would be on the wire.
func signSetupDevice20(t *testing.T, signer crypto.Signer, payload SetupDevice20Payload) *cose.Sign1[SetupDevice20Payload, []byte] {
	t.Helper()
	s1 := cose.Sign1[SetupDevice20Payload, []byte]{Payload: cbor.NewByteWrap(payload)}
	if err := s1.Sign(signer, nil, cose.AADSetupDevice, nil); err != nil {
		t.Fatal(err)
	}
	b, err := cbor.Marshal(s1.Tag())
	if err != nil {
		t.Fatal(err)
	}
	var out cose.Sign1Tag[SetupDevice20Payload, []byte]
	if err := cbor.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out.Untag()
}

func TestCheckSetupDevice20(t *testing.T) {
	ownerKey, _ := newTestKey(t)
	owner2Key, owner2Pub := newTestKey(t)
	otherKey, _ := newTestKey(t)
	var nonce, otherNonce protocol.Nonce
	_, _ = rand.Read(nonce[:])
	_, _ = rand.Read(otherNonce[:])
	sz := uint16(1300)

	resale := func(n protocol.Nonce) SetupDevice20Payload {
		return SetupDevice20Payload{
			DispositionCode: DispResale,
			ReplacementCred: &ReplacementCred20{
				GUID:            protocol.GUID{9},
				NonceTO2SetupDv: n,
				Owner2PubKey:    owner2Pub,
			},
			MaxDeviceServiceInfoSz: &sz,
		}
	}
	reuse := SetupDevice20Payload{DispositionCode: DispCredReuse, MaxDeviceServiceInfoSz: &sz}

	for _, tc := range []struct {
		name       string
		signer     crypto.Signer
		payload    SetupDevice20Payload
		allowReuse bool
		wantErr    string // empty: success
		wantResale bool
	}{
		{"resale signed by Owner2", owner2Key, resale(nonce), false, "", true},
		{"resale signed by Owner (not Owner2)", ownerKey, resale(nonce), false, "Owner2PubKey", false},
		{"resale wrong nonce", owner2Key, resale(otherNonce), false, "nonce mismatch", false},
		{"resale missing ReplacementCred", owner2Key, SetupDevice20Payload{DispositionCode: DispResale}, false, "without ReplacementCred", false},
		{"reuse signed by ProveOVHdr signer", ownerKey, reuse, true, "", false},
		{"reuse signed by other key", otherKey, reuse, true, "ProveOVHdr20 signer", false},
		{"reuse not allowed", ownerKey, reuse, false, "not allowed", false},
		{"reuse with ReplacementCred", ownerKey, SetupDevice20Payload{DispositionCode: DispCredReuse, ReplacementCred: resale(nonce).ReplacementCred}, true, "must not carry", false},
		{"disable unsupported", ownerKey, SetupDevice20Payload{DispositionCode: DispDisable}, true, "not supported", false},
		{"unknown disposition", ownerKey, SetupDevice20Payload{DispositionCode: 9}, true, "unknown DispositionCode", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setup := signSetupDevice20(t, tc.signer, tc.payload)
			partial, err := checkSetupDevice20(setup, nonce, ownerKey.Public(), nil, tc.allowReuse)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("got err %v, want error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if (partial != nil) != tc.wantResale {
				t.Fatalf("got replacement credentials %v, want resale=%v", partial, tc.wantResale)
			}
		})
	}
}

func TestCheckSetupDevice20TamperedSignature(t *testing.T) {
	owner2Key, owner2Pub := newTestKey(t)
	var nonce protocol.Nonce
	_, _ = rand.Read(nonce[:])
	setup := signSetupDevice20(t, owner2Key, SetupDevice20Payload{
		DispositionCode: DispResale,
		ReplacementCred: &ReplacementCred20{NonceTO2SetupDv: nonce, Owner2PubKey: owner2Pub},
	})
	setup.Signature[len(setup.Signature)-1] ^= 0x01
	if _, err := checkSetupDevice20(setup, nonce, nil, nil, false); err == nil {
		t.Fatal("tampered SetupDevice20 signature was accepted")
	}
}

func TestParseProveDevice20EAT(t *testing.T) {
	guid := protocol.GUID{1, 2, 3}
	var nonce, otherNonce protocol.Nonce
	_, _ = rand.Read(nonce[:])
	_, _ = rand.Read(otherNonce[:])
	payload := ProveDevice20Payload{
		KexSuiteName:        "ECDH256",
		CipherSuiteName:     1,
		XAKeyExchange:       []byte{1, 2, 3},
		NonceTO2ProveOVPrep: otherNonce,
		HashPrev2:           protocol.Hash{Algorithm: protocol.Sha256Hash, Value: make([]byte, 32)},
	}

	// Round-trip through CBOR, as the Owner sees it on the wire
	b, err := cbor.Marshal(newProveDevice20EAT(guid, nonce, payload))
	if err != nil {
		t.Fatal(err)
	}
	var eat eatoken
	if err := cbor.Unmarshal(b, &eat); err != nil {
		t.Fatal(err)
	}

	got, err := parseProveDevice20EAT(eat, nonce, guid)
	if err != nil {
		t.Fatal(err)
	}
	if got.KexSuiteName != payload.KexSuiteName || got.NonceTO2ProveOVPrep != payload.NonceTO2ProveOVPrep {
		t.Fatalf("payload did not round-trip: %+v", got)
	}
	if _, err := parseProveDevice20EAT(eat, otherNonce, guid); err == nil {
		t.Error("EAT with wrong NonceTO2ProveDv was accepted")
	}
	if _, err := parseProveDevice20EAT(eat, nonce, protocol.GUID{7}); err == nil {
		t.Error("EAT with wrong UEID was accepted")
	}
}

func TestHashMessage(t *testing.T) {
	for _, alg := range []protocol.HashAlg{protocol.Sha256Hash, protocol.Sha384Hash} {
		h, err := hashMessage(alg, []byte("msg"))
		if err != nil || len(h.Value) != alg.HashFunc().Size() {
			t.Errorf("hashMessage(%v) = %v, %v", alg, h, err)
		}
	}
	if _, err := hashMessage(protocol.HmacSha256Hash, []byte("msg")); err == nil {
		t.Error("hashMessage accepted an HMAC algorithm")
	}
}

func TestTo1dPayloadV20(t *testing.T) {
	ownerKey, _ := newTestKey(t)
	payload := protocol.To1d{
		To0dHash:      protocol.Hash{Algorithm: protocol.Sha256Hash, Value: make([]byte, 32)},
		DelegateChain: cbor.NewBstr[*[]*cbor.X509Certificate](nil),
	}
	b, err := cbor.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var elems []cbor.RawBytes
	if err := cbor.Unmarshal(b, &elems); err != nil {
		t.Fatal(err)
	}
	if len(elems) != 3 {
		t.Fatalf("FDO 2.0 to1d payload has %d elements, want 3", len(elems))
	}
	// DelegateChain is bstr .cbor null
	var chain []byte
	if err := cbor.Unmarshal(elems[2], &chain); err != nil || len(chain) != 1 || chain[0] != 0xf6 {
		t.Fatalf("DelegateChain = %x (%v), want bstr(h'f6')", []byte(elems[2]), err)
	}

	// FDO 1.1 form (no DelegateChain) still decodes
	b11, err := cbor.Marshal(protocol.To1d{To0dHash: payload.To0dHash})
	if err != nil {
		t.Fatal(err)
	}
	var to1d protocol.To1d
	if err := cbor.Unmarshal(b11, &to1d); err != nil || to1d.DelegateChain != nil {
		t.Fatalf("FDO 1.1 to1d did not decode: %v %+v", err, to1d)
	}

	// TO1.RVRedirect wrapper
	s1 := cose.Sign1[protocol.To1d, []byte]{Payload: cbor.NewByteWrap(payload)}
	if err := s1.Sign(ownerKey, nil, cose.AADOwnerSign, nil); err != nil {
		t.Fatal(err)
	}
	good := rvRedirect20{NumTo1ds: 1, MsgTo1ds: []cose.Sign1Tag[protocol.To1d, []byte]{*s1.Tag()}}
	if _, err := firstTo1d(good); err != nil {
		t.Errorf("valid RVRedirect rejected: %v", err)
	}
	for _, bad := range []rvRedirect20{
		{NumTo1ds: 0},
		{NumTo1ds: 1, IdxTo1ds: 1, MsgTo1ds: good.MsgTo1ds},
		{NumTo1ds: 0, MsgTo1ds: good.MsgTo1ds},
	} {
		if _, err := firstTo1d(bad); err == nil {
			t.Errorf("malformed RVRedirect accepted: %+v", bad)
		}
	}
}
