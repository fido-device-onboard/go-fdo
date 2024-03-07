// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
)

// Define a new private type so that key cannot be created outside of this
// library.
type contextKey struct{}

// Context key to hold mutable ErrorMessage.
var errMsgContextKey contextKey

// Helper function to add a mutable ErrorMessage value to a context. This
// should be called before starting a protocol so that ErrorMessage data can be
// captured directly at the error point.
func contextWithErrMsg(parent context.Context) context.Context {
	var errMsg ErrorMessage
	return context.WithValue(parent, errMsgContextKey, &errMsg)
}

func errMsgFromContext(ctx context.Context) *ErrorMessage {
	return ctx.Value(errMsgContextKey).(*ErrorMessage)
}

// Set the PrevMsgType of the ErrorMessage value in the context.
//
// If the provided context does not have an *ErrorMessage for errMsgContextKey
// then this function panics, because it is a programming error to try to
// capture an error outside of a protocol implementation.
func captureMsgType(ctx context.Context, msgType uint8) {
	errMsgFromContext(ctx).PrevMsgType = msgType
}

// Use provided data to set the ErrorMessage value in the context. The zero
// values may be provided so that defaults are used when sending the
// ErrorMessage.
//
// If the provided context does not have an *ErrorMessage for errMsgContextKey
// then this function panics, because it is a programming error to try to
// capture an error outside of a protocol implementation.
func captureErr(ctx context.Context, code uint16, err string) {
	errMsgFromContext(ctx).Code = code
	errMsgFromContext(ctx).ErrString = err
}
