// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package http

import (
	"context"
	"encoding/hex"
	"log/slog"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cbor/cdn"
)

func debugEnabled() bool {
	return slog.Default().Enabled(context.Background(), slog.LevelDebug)
}

func tryDebugNotation(b []byte) string {
	d, err := cdn.FromCBOR(b)
	if err != nil {
		return hex.EncodeToString(b)
	}
	return d
}

func debugUnencryptedMessage(msgType uint8, msg any) {
	if debugEnabled() {
		return
	}
	body, _ := cbor.Marshal(msg)
	slog.Debug("unencrypted request", "msg", msgType, "body", tryDebugNotation(body))
}

func debugDecryptedMessage(msgType uint8, decrypted []byte) {
	if debugEnabled() {
		return
	}
	slog.Debug("decrypted response", "msg", msgType, "body", tryDebugNotation(decrypted))
}
