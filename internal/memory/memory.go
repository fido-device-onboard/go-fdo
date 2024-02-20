// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package memory implements server state using non-persistent memory to
// complement [internal/token.Service] for state that must persist between
// protocol sessions.
package memory

import (
	"context"

	"github.com/fido-device-onboard/go-fdo"
)

// State implements interfaces for state which must be persisted between
// protocol sessions, but not between server processes.
type State struct{}

var _ fdo.VoucherState = (*State)(nil)

// NewVoucher creates and stores a new voucher.
func (s *State) NewVoucher(context.Context, *fdo.Voucher) error

// Voucher retrieves a voucher by GUID.
func (s *State) Voucher(context.Context, fdo.GUID) (*fdo.Voucher, error)
