// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package http implements FDO transport interfaces using an HTTP protocol.
package http

import (
	"context"

	"github.com/fido-device-onboard/go-fdo/protocol"
)

// AuthorizationJar stores authorization tokens. Context parameters are used to
// allow passing arbitrary data which may be needed for thread-safe
// implementations.
type AuthorizationJar interface {
	Clear(context.Context, protocol.Protocol)
	GetToken(context.Context, protocol.Protocol) string
	StoreToken(context.Context, protocol.Protocol, string)
}

// The default AuthorizationJar implementation which does not support
// concurrent use.
type jar map[protocol.Protocol]string

var _ AuthorizationJar = jar(nil)

func (j jar) Clear(_ context.Context, prot protocol.Protocol) {
	if prot == protocol.UnknownProtocol {
		clear(j)
		return
	}
	delete(j, prot)
}
func (j jar) GetToken(_ context.Context, prot protocol.Protocol) string {
	return j[prot]
}
func (j jar) StoreToken(_ context.Context, prot protocol.Protocol, token string) {
	j[prot] = token
}
