// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package fsim implements common FSIM modules defined in
// https://github.com/fido-alliance/fdo-sim/tree/main/fsim-repository as well
// as plugin modules as defined in plugin/README.md.
package fsim

import (
	"context"
	"log/slog"
)

func debugEnabled() bool {
	return slog.Default().Enabled(context.Background(), slog.LevelDebug)
}
