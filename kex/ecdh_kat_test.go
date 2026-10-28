// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package kex

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"testing"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// ECDH known-answer vectors. ShSe = Shx || DeviceRandom || OwnerRandom by
// role (FDO spec, ECDH key exchange), so the SEK depends only on which
// parameter belongs to the Device, not on whether it travelled as xA (FDO 2.0,
// TO2.ProveDevice20) or xB (FDO 1.1, TO2.ProveDevice). Other implementations
// (fdo-uefi-rs, fido-device-onboard-rs) should reproduce these values.
//
// Inputs:
//
//	device private scalar = H("fdo-kat-device"), owner = H("fdo-kat-owner"),
//	H = SHA-256 for P-256, SHA-384 for P-384
//	DeviceRandom = 0x11 repeated, OwnerRandom = 0x22 repeated (16 / 48 bytes)
//	ECDH256 with A128GCM and A256GCM, ECDH384 with A256GCM (GCM suites: KDF
//	PRF is HMAC-SHA256)
//
// Shx and SEK were cross-checked with Python's cryptography package.
type ecdhKAT struct {
	name     string
	curve    ecdh.Curve
	hash     func([]byte) []byte
	randSize int
	cipher   CipherSuiteID
	shx      string
	sek      string
}

var ecdhKATs = []ecdhKAT{
	{
		name:     "ECDH256",
		curve:    ecdh.P256(),
		hash:     func(b []byte) []byte { h := sha256.Sum256(b); return h[:] },
		randSize: 16,
		cipher:   A128GcmCipher,
		shx:      "28ec90132b66e9cce5d13f52bd3408dece6be04d89a34a27b3b8ba3498a4b272",
		sek:      "1e834c3d7a72efe4c35460ab218d53fc",
	},
	{
		name:     "ECDH256-A256GCM",
		curve:    ecdh.P256(),
		hash:     func(b []byte) []byte { h := sha256.Sum256(b); return h[:] },
		randSize: 16,
		cipher:   A256GcmCipher,
		shx:      "28ec90132b66e9cce5d13f52bd3408dece6be04d89a34a27b3b8ba3498a4b272",
		sek:      "dd637b926fac42795349dc7898447da80c0c829534ba4cf9c4cac0822e5b63e2",
	},
	{
		name:     "ECDH384",
		curve:    ecdh.P384(),
		hash:     func(b []byte) []byte { h := sha512.Sum384(b); return h[:] },
		randSize: 48,
		cipher:   A256GcmCipher,
		shx:      "370e971edffc9475055272eb72c671b6da4edaf1c89b40fc3ce986d355790dd6bd94b647da67a88c4b4659507d30587a",
		sek:      "af6a6677b13b897354536835179b08d3f520e67fe0bf1874c23512b5ae42390e",
	},
}

func (v ecdhKAT) params(t *testing.T) (devKey, ownKey *ecdh.PrivateKey, devParam, ownParam []byte) {
	t.Helper()
	var err error
	if devKey, err = v.curve.NewPrivateKey(v.hash([]byte("fdo-kat-device"))); err != nil {
		t.Fatal(err)
	}
	if ownKey, err = v.curve.NewPrivateKey(v.hash([]byte("fdo-kat-owner"))); err != nil {
		t.Fatal(err)
	}
	marshal := func(k *ecdh.PrivateKey, fill byte) []byte {
		b, err := ecdhParam{Pub: k.PublicKey().Bytes(), Rand: bytes.Repeat([]byte{fill}, v.randSize)}.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	return devKey, ownKey, marshal(devKey, 0x11), marshal(ownKey, 0x22)
}

func TestECDHKnownAnswer(t *testing.T) {
	for _, v := range ecdhKATs {
		t.Run(v.name, func(t *testing.T) {
			devKey, ownKey, devParam, ownParam := v.params(t)

			shx, err := devKey.ECDH(ownKey.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(shx); got != v.shx {
				t.Errorf("Shx = %s, want %s", got, v.shx)
			}

			for _, tc := range []struct {
				name        string
				deviceSentA bool
			}{
				{"FDO 1.1 (Device sends xB)", false},
				{"FDO 2.0 (Device sends xA)", true},
			} {
				xA, xB := ownParam, devParam
				if tc.deviceSentA {
					xA, xB = devParam, ownParam
				}
				for side, key := range map[string]*ecdh.PrivateKey{"device": devKey, "owner": ownKey} {
					sek, _, err := ecdhSymmetricKey(key, xA, xB, tc.deviceSentA, v.cipher.Suite())
					if err != nil {
						t.Fatalf("%s, %s side: %v", tc.name, side, err)
					}
					if got := hex.EncodeToString(sek); got != v.sek {
						t.Errorf("%s, %s side: SEK = %s, want %s", tc.name, side, got, v.sek)
					}
				}
			}

			// Negative control: the pre-fix positional order at 2.0
			// (Shx || xB.Rand || xA.Rand with the Device in xA) must not match.
			sek, _, err := ecdhSymmetricKey(devKey, devParam, ownParam, false, v.cipher.Suite())
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(sek) == v.sek {
				t.Error("positional (Owner random first) order at 2.0 produced the role-based SEK")
			}
		})
	}
}

// TestECDHDeviceSentAPersists checks that the FDO 2.0 role flag survives a
// marshal/unmarshal between the Device's Parameter and SetParameter, and that
// a record without the trailing field (written before it existed) decodes.
func TestECDHDeviceSentAPersists(t *testing.T) {
	for _, suite := range []Suite{ECDH256Suite, ECDH384Suite} {
		t.Run(string(suite), func(t *testing.T) {
			device := suite.New(nil, A128GcmCipher)
			SetDeviceSentA(device)
			xA, err := device.Parameter(rand.Reader, nil)
			if err != nil {
				t.Fatal(err)
			}

			b, err := device.(*ECDHSession).MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			restored := suite.New(nil, A128GcmCipher).(*ECDHSession)
			if err := restored.UnmarshalBinary(b); err != nil {
				t.Fatal(err)
			}
			if !restored.deviceSentA {
				t.Fatal("deviceSentA lost across marshal/unmarshal")
			}

			owner := suite.New(xA, A128GcmCipher)
			SetDeviceSentA(owner)
			xB, err := owner.Parameter(rand.Reader, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := restored.SetParameter(xB, nil); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(restored.SEK, owner.(*ECDHSession).SEK) {
				t.Fatal("Device and Owner SEK differ")
			}

			// Old 7-element record (no DeviceSentA): decodes, flag false.
			old, err := cbor.Marshal([]any{16, []byte{}, []byte{}, []byte{}, A128GcmCipher, []byte{}, []byte{}})
			if err != nil {
				t.Fatal(err)
			}
			var legacy ECDHSession
			legacy.randSize = 16
			if err := legacy.UnmarshalBinary(old); err != nil {
				t.Fatalf("legacy record: %v", err)
			}
			if legacy.deviceSentA {
				t.Fatal("legacy record decoded with deviceSentA set")
			}
		})
	}
}
