// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package http

import (
	"context"

	"github.com/fido-device-onboard/go-fdo"
)

// AuthorizationJar stores authorization tokens. Context parameters are used to
// allow passing arbitrary data which may be needed for thread-safe
// implementations.
type AuthorizationJar interface {
	Clear(ctx context.Context)
	GetToken(ctx context.Context, msgType uint8) string
	StoreToken(ctx context.Context, msgType uint8, token string)
}

// The default AuthorizationJar implementation which does not support
// concurrent use.
type jar map[fdo.Protocol]string

var _ AuthorizationJar = jar(nil)

func (j jar) Clear(context.Context) {
	clear(j)
}
func (j jar) GetToken(_ context.Context, msgType uint8) string {
	return j[fdo.ProtocolOf(msgType)]
}
func (j jar) StoreToken(_ context.Context, msgType uint8, token string) {
	j[fdo.ProtocolOf(msgType)] = token
}
