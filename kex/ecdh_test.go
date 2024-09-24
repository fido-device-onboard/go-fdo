// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package kex_test

import (
	"crypto/rand"
	"testing"

	"github.com/fido-device-onboard/go-fdo/kex"
)

func TestECDHExchange(t *testing.T) {
	for _, suite := range []kex.Suite{kex.ECDH256Suite, kex.ECDH384Suite} {
		t.Run(string(suite), testSuite(suite))
	}
}

func TestBadECDH256Exchange(t *testing.T) {
	serverSess := kex.ECDH256Suite.New(nil, kex.A128GcmCipher)
	xA, err := serverSess.Parameter(rand.Reader, nil)
	if err != nil {
		t.Fatal(err)
	}

	clientSess := kex.ECDH384Suite.New(xA, kex.A128GcmCipher)
	if _, err := clientSess.Parameter(rand.Reader, nil); err == nil {
		t.Fatal("expected error creating parameter with wrong curve")
	}
}
