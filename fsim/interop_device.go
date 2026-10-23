// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// Interop implements https://github.com/fido-alliance/conformance-test-tools-resources/blob/821c7114ae193148d276464a80c98d5535fa5681/docs/FDO/Pre-Interop/Step-by-step.md?plain=1#L36
// and should be registered to the "fido_alliance" module. It prints the
// dashboard token to the logger output.
type Interop struct{}

var _ serviceinfo.DeviceModule = (*Interop)(nil)

// Transition implements serviceinfo.DeviceModule.
func (d *Interop) Transition(active bool) error { return nil }

// Receive implements serviceinfo.DeviceModule.
func (d *Interop) Receive(ctx context.Context, messageName string, messageBody io.Reader, respond func(string) io.Writer, yield func()) error {
	switch messageName {
	case "dev_conformance":
		var token string
		if err := cbor.NewDecoder(messageBody).Decode(token); err != nil {
			return err
		}
		slog.Info("FIDO Alliance interop dashboard", "access token", token)
		return nil

	default:
		return fmt.Errorf("unknown message %s", messageName)
	}
}

// Yield implements serviceinfo.DeviceModule.
func (d *Interop) Yield(ctx context.Context, respond func(message string) io.Writer, yield func()) error {
	return nil
}
