// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cose_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
)

func TestEC2Key(t *testing.T) {
	// {
	//   1:2,
	//   2:'meriadoc.brandybuck@buckland.example',
	//   -1:1,
	//   -2:h'65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d',
	//   -3:h'1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c',
	//   -4:h'aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf'
	// },
	t.Run("P-256 Decode Fixture", func(t *testing.T) {
		// d, _ := hex.DecodeString("aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf")

		c, _ := hex.DecodeString("A501020258246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65200121582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D2258201E52ED75701163F7F9E40DDF9F341B3DC9BA860AF7E0CA7CA7E9EECD0084D19C")
		var key cose.Key
		if err := cbor.Unmarshal(c, &key); err != nil {
			t.Fatal(err)
		}
		pub, err := key.Public()
		if err != nil {
			t.Fatal(err)
		}
		ecpub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			t.Fatal("not an EC public key")
		}
		if ecpub.Curve != elliptic.P256() {
			t.Fatal("not a P-256 key")
		}
	})

	t.Run("P-384 Encode/Decode", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub := key.Public()
		ckey, err := cose.NewKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		b, err := cbor.Marshal(ckey)
		if err != nil {
			t.Fatal(err)
		}
		var ckey2 cose.Key
		if err := cbor.Unmarshal(b, &ckey2); err != nil {
			t.Fatal(err)
		}
		cpub, err := ckey2.Public()
		if err != nil {
			t.Fatal(err)
		}
		pub2, ok := cpub.(*ecdsa.PublicKey)
		if !ok {
			t.Fatal("expected to parse an EC2 public key")
		}
		if !pub2.Equal(pub) {
			t.Fatal("expected public keys to match")
		}
	})

	// {
	//   1:2,
	//   2:'bilbo.baggins@hobbiton.example',
	//   -1:3,
	//   -2:h'0072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad',
	//   -3:h'01dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d9475',
	//   -4:h'00085138ddabf5ca975f5860f91a08e91d6d5f9a76ad4018766a476680b55cd339e8ab6c72b5facdb2a2a50ac25bd086647dd3e2e6e99e84ca2c3609fdf177feb26d'
	// },
	t.Run("P-521 Decode Fixture", func(t *testing.T) {
		// d, _ := hex.DecodeString("00085138ddabf5ca975f5860f91a08e91d6d5f9a76ad4018766a476680b55cd339e8ab6c72b5facdb2a2a50ac25bd086647dd3e2e6e99e84ca2c3609fdf177feb26d")

		c, _ := hex.DecodeString("A5010202581E62696C626F2E62616767696E7340686F626269746F6E2E6578616D706C6520032158420072992CB3AC08ECF3E5C63DEDEC0D51A8C1F79EF2F82F94F3C737BF5DE7986671EAC625FE8257BBD0394644CAAA3AAF8F27A4585FBBCAD0F2457620085E5C8F42AD22584201DCA6947BCE88BC5790485AC97427342BC35F887D86D65A089377E247E60BAA55E4E8501E2ADA5724AC51D6909008033EBC10AC999B9D7F5CC2519F3FE1EA1D9475")
		var key cose.Key
		if err := cbor.Unmarshal(c, &key); err != nil {
			t.Fatal(err)
		}
		pub, err := key.Public()
		if err != nil {
			t.Fatal(err)
		}
		ecpub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			t.Fatal("not an EC public key")
		}
		if ecpub.Curve != elliptic.P521() {
			t.Fatal("not a P-521 key")
		}
	})
}
