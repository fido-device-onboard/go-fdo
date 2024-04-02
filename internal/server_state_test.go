// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package internal_test

import (
	"testing"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/fdotest"
	"github.com/fido-device-onboard/go-fdo/internal/memory"
	"github.com/fido-device-onboard/go-fdo/internal/token"
)

func TestServerState(t *testing.T) {
	stateless, err := token.NewService()
	if err != nil {
		t.Fatal(err)
	}
	inMemory, err := memory.NewState()
	if err != nil {
		t.Fatal(err)
	}
	state := struct {
		fdo.TokenService
		fdo.DISessionState
		fdo.TO1SessionState
		fdo.TO2SessionState
		fdo.RendezvousBlobPersistentState
		fdo.VoucherPersistentState
		fdo.OwnerKeyPersistentState
	}{
		TokenService:                  stateless,
		DISessionState:                stateless,
		TO1SessionState:               stateless,
		TO2SessionState:               stateless,
		RendezvousBlobPersistentState: inMemory,
		VoucherPersistentState:        inMemory,
		OwnerKeyPersistentState:       inMemory,
	}

	fdotest.TestServerState(state, t)
}
