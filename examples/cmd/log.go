// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"log/slog"
	"os"

	"hermannm.dev/devlog"
)

var level slog.LevelVar

func init() {
	slog.SetDefault(slog.New(devlog.NewHandler(os.Stdout, &devlog.Options{
		Level: &level,
	})))
}
