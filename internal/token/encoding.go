// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

type state[T any] interface {
	*T
	id() []byte
}

func newToken[T state[U], U any](secret []byte) (string, error) {
	v := T(new(U))
	if _, err := rand.Read(v.id()); err != nil {
		return "", err
	}
	return toToken(v, secret)
}

func toToken[T state[U], U any](v T, secret []byte) (string, error) {
	payload, err := cbor.Marshal(v)
	if err != nil {
		return "", err
	}

	mac := hmac.New(sha512.New384, secret)
	_, _ = mac.Write(payload)
	macAndPayload := append(mac.Sum(nil)[:], payload...)

	return base64.RawURLEncoding.EncodeToString(macAndPayload), nil
}

func fromToken[T state[U], U any](s string, secret []byte) (T, error) {
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

	v := new(U)
	if err := cbor.Unmarshal(payload, v); err != nil {
		return nil, err
	}
	return v, nil
}
