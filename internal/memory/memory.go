// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package memory implements server state using non-persistent memory to
// complement [internal/token.Service] for state that must persist between
// protocol sessions.
package memory

import (
	"context"
	"fmt"

	"github.com/fido-device-onboard/go-fdo"
)

// State implements interfaces for state which must be persisted between
// protocol sessions, but not between server processes.
type State struct {
	Vouchers map[fdo.GUID]*fdo.Voucher
}

var _ fdo.VoucherState = (*State)(nil)

// NewState initializes the in-memory state.
func NewState() *State {
	return &State{
		Vouchers: make(map[fdo.GUID]*fdo.Voucher),
	}
}

// NewVoucher creates and stores a new voucher.
func (s *State) NewVoucher(_ context.Context, ov *fdo.Voucher) error {
	s.Vouchers[ov.Header.Val.GUID] = ov
	return nil
}

// Voucher retrieves a voucher by GUID.
func (s *State) Voucher(_ context.Context, guid fdo.GUID) (*fdo.Voucher, error) {
	ov, ok := s.Vouchers[guid]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return ov, nil
}
