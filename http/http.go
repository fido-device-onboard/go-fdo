// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package http implements FDO transport interfaces using an HTTP protocol.
package http

import (
	"context"

	"github.com/fido-device-onboard/go-fdo"
)

// AuthorizationJar stores authorization tokens. Context parameters are used to
// allow passing arbitrary data which may be needed for thread-safe
// implementations.
type AuthorizationJar interface {
	Clear(context.Context, fdo.Protocol)
	GetToken(context.Context, fdo.Protocol) string
	StoreToken(context.Context, fdo.Protocol, string)
}

// The default AuthorizationJar implementation which does not support
// concurrent use.
type jar map[fdo.Protocol]string

var _ AuthorizationJar = jar(nil)

func (j jar) Clear(_ context.Context, prot fdo.Protocol) {
	if prot == fdo.UnknownProtocol {
		clear(j)
		return
	}
	delete(j, prot)
}
func (j jar) GetToken(_ context.Context, prot fdo.Protocol) string {
	return j[prot]
}
func (j jar) StoreToken(_ context.Context, prot fdo.Protocol, token string) {
	j[prot] = token
}
