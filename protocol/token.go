// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package protocol

import "context"

// TokenService maintains state related to the authorization header or similar
// token. The purpose of the token is to link API calls to their protocol
// context within the message stream defined by the FIDO Device Onboard
// Protocols. The handler for a subsequent message can find this stored state
// by looking it up using the token as a key.
type TokenService interface {
	// NewToken initializes state for a given protocol and return the
	// associated token.
	NewToken(context.Context, Protocol) (string, error)

	// InvalidateToken destroys the state associated with a given token.
	// fdo.ErrNotFound or an error wrapping it must be returned if the token
	// has already been invalidated.
	InvalidateToken(context.Context) error

	// TokenContext injects a context with a token value so that it may be used
	// for any of the XXXState interfaces.
	TokenContext(context.Context, string) context.Context

	// TokenFromContext gets the token value from a context. This is useful,
	// because some TokenServices may allow token mutation, such as in the case
	// of token-encoded state (i.e. JWTs/CWTs).
	TokenFromContext(context.Context) (string, bool)
}
