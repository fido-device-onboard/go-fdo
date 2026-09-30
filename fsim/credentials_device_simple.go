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

// SimpleCredentialsDevice implements a simplified fdo.credentials FSIM for device-side credential reception.
// This follows the sysconfig pattern - simple CBOR messages, no chunking.
type SimpleCredentialsDevice struct {
	// Callback for credential handling
	OnCredential func(id, credType string, data []byte, metadata map[string]any) error
}

var _ serviceinfo.DeviceModule = (*SimpleCredentialsDevice)(nil)

// Transition implements serviceinfo.DeviceModule.
func (c *SimpleCredentialsDevice) Transition(active bool) error {
	return nil
}

// Yield implements serviceinfo.DeviceModule.
func (c *SimpleCredentialsDevice) Yield(ctx context.Context, respond func(string) io.Writer, yield func()) error {
	return nil
}

// Receive implements serviceinfo.DeviceModule.
func (c *SimpleCredentialsDevice) Receive(ctx context.Context, messageName string, messageBody io.Reader, respond func(string) io.Writer, yield func()) error {
	switch messageName {
	case "credential":
		var cred SimpleCredential
		if err := cbor.NewDecoder(messageBody).Decode(&cred); err != nil {
			return fmt.Errorf("error decoding credential: %w", err)
		}

		slog.Debug("[fdo.credentials] Received credential", "id", cred.ID, "type", cred.Type)

		if c.OnCredential != nil {
			if err := c.OnCredential(cred.ID, cred.Type, cred.Data, cred.Metadata); err != nil {
				return fmt.Errorf("credential handler error: %w", err)
			}
		}
		return nil

	default:
		// Silently ignore unknown messages (like active)
		return nil
	}
}

// NewSimpleCredentialsDevice creates a new SimpleCredentialsDevice.
func NewSimpleCredentialsDevice(onCredential func(id, credType string, data []byte, metadata map[string]any) error) *SimpleCredentialsDevice {
	return &SimpleCredentialsDevice{
		OnCredential: onCredential,
	}
}
