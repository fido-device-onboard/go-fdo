// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package kex_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding"
	"reflect"
	"testing"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/kex"
)

func testSuite(suite kex.Suite) func(t *testing.T) {
	return func(t *testing.T) {
		ownerKey, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			t.Fatal(err)
		}

		serverSess := suite.New(nil, kex.A128GcmCipher)
		xA, err := serverSess.Parameter(rand.Reader, &ownerKey.PublicKey)
		if err != nil {
			t.Fatal(err)
		}

		testEncodeDecode(t, suite, serverSess)

		clientSess := suite.New(xA, kex.A128GcmCipher)
		xB, err := clientSess.Parameter(rand.Reader, &ownerKey.PublicKey)
		if err != nil {
			t.Fatal(err)
		}

		testEncodeDecode(t, suite, clientSess)

		if err := serverSess.SetParameter(xB, ownerKey); err != nil {
			t.Fatal(err)
		}

		testEncodeDecode(t, suite, serverSess)

		if !bytes.Equal(
			reflect.ValueOf(serverSess).Elem().FieldByName("SEK").Bytes(),
			reflect.ValueOf(clientSess).Elem().FieldByName("SEK").Bytes(),
		) {
			t.Fatal("expected client and server sessions to have matching symmetric keys")
		}

		if len(reflect.ValueOf(serverSess).Elem().FieldByName("SVK").Bytes()) > 0 ||
			len(reflect.ValueOf(clientSess).Elem().FieldByName("SVK").Bytes()) > 0 {
			t.Fatal("expected client and server sessions to have no SVK")
		}

		type example struct {
			A int
			B []byte
			C struct {
				D string
				E uint
			}
		}
		expect := example{
			A: 7,
			B: []byte{0x00, 0x01, 0x02},
			C: struct {
				D string
				E uint
			}{
				D: "Hello world!",
				E: 0,
			},
		}

		encrypted, err := serverSess.Encrypt(rand.Reader, expect)
		if err != nil {
			t.Fatal(err)
		}

		var buf bytes.Buffer
		if err := cbor.NewEncoder(&buf).Encode(encrypted); err != nil {
			t.Fatal(err)
		}

		decrypted, err := clientSess.Decrypt(rand.Reader, &buf)
		if err != nil {
			t.Fatal(err)
		}

		var got example
		if err := cbor.Unmarshal(decrypted, &got); err != nil {
			t.Fatal(err)
		}

		if !reflect.DeepEqual(expect, got) {
			t.Fatalf("expected %#v, got %#v", expect, got)
		}
	}
}

func testEncodeDecode(t *testing.T, suite kex.Suite, sess kex.Session) {
	data, err := sess.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	load := suite.New(nil, kex.A128GcmCipher)
	if err := load.(encoding.BinaryUnmarshaler).UnmarshalBinary(data); err != nil {
		t.Fatal(err)
	}

	if equaler, ok := sess.(interface{ Equal(kex.Session) bool }); ok {
		if !equaler.Equal(load) {
			t.Fatalf("session encode/decode:\nexpected %s\ngot %s", sess, load)
		}
	} else if !reflect.DeepEqual(sess, load) {
		t.Fatalf("session encode/decode:\nexpected %s\ngot %s", sess, load)
	}
}
