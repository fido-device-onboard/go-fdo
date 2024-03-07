// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package kex_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/fido-device-onboard/go-fdo/kex"
)

func TestECDH256Exchange(t *testing.T) {
	serverSess := kex.ECDH256Suite.New(nil, kex.A128GcmCipher)
	xA, err := serverSess.Parameter(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	clientSess := kex.ECDH256Suite.New(xA, kex.A128GcmCipher)
	xB, err := clientSess.Parameter(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if err := serverSess.SetParameter(xB); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(
		serverSess.(*kex.ECDHSession).SEK,
		clientSess.(*kex.ECDHSession).SEK,
	) {
		t.Fatal("expected client and server sessions to have matching symmetric keys")
	}

	if len(serverSess.(*kex.ECDHSession).SVK) > 0 ||
		len(clientSess.(*kex.ECDHSession).SVK) > 0 {
		t.Fatal("expected client and server sessions to have no SVK")
	}
}

func TestBadECDH256Exchange(t *testing.T) {
	serverSess := kex.ECDH256Suite.New(nil, kex.A128GcmCipher)
	xA, err := serverSess.Parameter(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	clientSess := kex.ECDH384Suite.New(xA, kex.A128GcmCipher)
	if _, err := clientSess.Parameter(rand.Reader); err == nil {
		t.Fatal("expected error creating parameter with wrong curve")
	}
}
