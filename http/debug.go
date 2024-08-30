// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package http

import (
	"context"
	"encoding/hex"
	"log/slog"

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
