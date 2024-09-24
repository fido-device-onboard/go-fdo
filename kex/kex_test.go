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

	if !reflect.DeepEqual(sess, load) {
		t.Fatalf("session encode/decode:\nexpected %s\ngot %s", sess, load)
	}
}
