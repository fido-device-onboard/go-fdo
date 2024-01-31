// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package kex

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestECDH256Exchange(t *testing.T) {
	serverSess := ECDH256Suite.New(nil, A128GcmCipher)
	xA, err := serverSess.Parameter(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	clientSess := ECDH256Suite.New(xA, A128GcmCipher)
	xB, err := clientSess.Parameter(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if err := serverSess.SetParameter(xB); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(
		serverSess.(*ecdhSession).sek,
		clientSess.(*ecdhSession).sek,
	) {
		t.Fatal("expected client and server sessions to have matching symmetric keys")
	}
}
