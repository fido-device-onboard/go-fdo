// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package token

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// Unique provides randomness to a token before any state is set.
type Unique struct {
	Random [16]byte
}

func (u *Unique) id() []byte { return u.Random[:] }

type statePtr[T state] interface {
	*T
	id() []byte
}

type state interface {
	diState | to1State | to2State
}

func newToken[P statePtr[T], T state](secret []byte) (string, error) {
	var v T
	if _, err := rand.Read(P(&v).id()); err != nil {
		return "", err
	}
	return toToken(v, secret)
}

func toToken[T state](v T, secret []byte) (string, error) {
	payload, err := cbor.Marshal(v)
	if err != nil {
		return "", err
	}

	mac := hmac.New(sha512.New384, secret)
	_, _ = mac.Write(payload)
	macAndPayload := append(mac.Sum(nil)[:], payload...)

	return base64.RawURLEncoding.EncodeToString(macAndPayload), nil
}

func fromToken[T state](s string, secret []byte) (*T, error) {
	macAndPayload, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(macAndPayload) < 48 {
		return nil, ErrInvalidToken
	}

	mac1, payload := macAndPayload[:48], macAndPayload[48:]
	verify := hmac.New(sha512.New384, secret)
	_, _ = verify.Write(payload)
	mac2 := verify.Sum(nil)[:]
	if !hmac.Equal(mac1, mac2) {
		return nil, ErrInvalidToken
	}

	v := new(T)
	if err := cbor.Unmarshal(payload, v); err != nil {
		return nil, err
	}
	return v, nil
}

func fetch[S state, T any](ctx context.Context, s Service, f func(S) (T, error)) (T, error) {
	var result T
	token, ok := s.TokenFromContext(ctx)
	if !ok {
		return result, ErrInvalidToken
	}
	state, err := fromToken[S](token, s.HmacSecret)
	if err != nil {
		return result, err
	}
	return f(*state)
}

func update[S state](ctx context.Context, s Service, f func(*S) error) error {
	token, ok := ctx.Value(key).(*string)
	if !ok {
		return ErrInvalidToken
	}
	state, err := fromToken[S](*token, s.HmacSecret)
	if err != nil {
		return err
	}
	if err := f(state); err != nil {
		return err
	}
	newToken, err := toToken(*state, s.HmacSecret)
	if err != nil {
		return err
	}
	*token = newToken
	return nil
}
