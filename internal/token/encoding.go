// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package token

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
)

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
		return nil, errInvalidToken
	}

	mac1, payload := macAndPayload[:48], macAndPayload[48:]
	verify := hmac.New(sha512.New384, secret)
	_, _ = verify.Write(payload)
	mac2 := verify.Sum(nil)[:]
	if !hmac.Equal(mac1, mac2) {
		return nil, errInvalidToken
	}

	var v T
	if err := cbor.Unmarshal(payload, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// SetupDeviceNonce returns the Nonce used in TO2.SetupDevice and TO2.Done2.
func (s Service) SetupDeviceNonce(ctx context.Context) (fdo.Nonce, error) {
	return fetch[to2State, fdo.Nonce](ctx, s, func(state to2State) (fdo.Nonce, error) {
		if state.SetupDv == (fdo.Nonce{}) {
			return fdo.Nonce{}, errNotFound
		}
		return state.SetupDv, nil
	})
}

func fetch[S state, T any](ctx context.Context, s Service, f func(S) (T, error)) (T, error) {
	var result T
	token, ok := s.TokenFromContext(ctx)
	if !ok {
		return result, errInvalidToken
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
		return errInvalidToken
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
