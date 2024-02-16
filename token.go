// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import "context"

// TokenService manages generating and decoding tokens.
type TokenService interface {
	NewSession(context.Context) (string, error)
}
