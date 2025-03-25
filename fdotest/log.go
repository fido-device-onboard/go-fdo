// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdotest

import (
	"bytes"
	"io"
	"testing"
)

// TestingLog creates a testing logger.
func TestingLog(t *testing.T) io.Writer { return (*errorLog)(t) }

type errorLog testing.T

// Write implements io.Writer.
func (t *errorLog) Write(p []byte) (int, error) {
	(*testing.T)(t).Helper()
	t.Log(string(bytes.TrimSpace(p)))
	return len(p), nil
}
