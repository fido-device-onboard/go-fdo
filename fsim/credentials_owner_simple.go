// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// SimpleCredentialsOwner implements a simplified fdo.credentials FSIM for owner-side credential provisioning.
// This follows the sysconfig pattern - simple CBOR messages, no chunking.
type SimpleCredentialsOwner struct {
	// Credentials to provision
	Credentials []SimpleCredential

	// Internal state
	credIndex  int
	sentActive bool
}

// SimpleCredential represents a credential to provision.
type SimpleCredential struct {
	ID       string         `cbor:"id"`
	Type     string         `cbor:"type"`
	Data     []byte         `cbor:"data"`
	Metadata map[string]any `cbor:"metadata,omitempty"`
}

var _ serviceinfo.OwnerModule = (*SimpleCredentialsOwner)(nil)

// HandleInfo implements serviceinfo.OwnerModule.
func (c *SimpleCredentialsOwner) HandleInfo(ctx context.Context, messageName string, messageBody io.Reader) error {
	// Like sysconfig, we don't expect responses from device for simple credential provisioning
	// Just silently ignore any messages, but we MUST read the full body
	_, _ = io.Copy(io.Discard, messageBody)
	slog.Debug("[fdo.credentials] Received message (ignoring)", "name", messageName)
	return nil
}

// ProduceInfo implements serviceinfo.OwnerModule.
func (c *SimpleCredentialsOwner) ProduceInfo(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	// Send active message first if we have credentials to send
	// NOTE: Do NOT return early after sending active - continue to send credentials
	// in the same call to avoid token change issues between TO2 rounds
	if !c.sentActive && len(c.Credentials) > 0 {
		if err := producer.WriteChunk("active", []byte{0xf5}); err != nil { // CBOR true
			return false, false, fmt.Errorf("error sending active message: %w", err)
		}
		c.sentActive = true
	}

	// Send credentials one at a time
	if c.credIndex < len(c.Credentials) {
		cred := c.Credentials[c.credIndex]
		c.credIndex++

		// Encode credential as CBOR
		var buf bytes.Buffer
		if err := cbor.NewEncoder(&buf).Encode(cred); err != nil {
			return false, false, fmt.Errorf("error encoding credential: %w", err)
		}

		if err := producer.WriteChunk("credential", buf.Bytes()); err != nil {
			return false, false, fmt.Errorf("error sending credential: %w", err)
		}

		slog.Debug("[fdo.credentials] Sent credential", "id", cred.ID, "type", cred.Type)
		return false, false, nil
	}

	// All credentials sent, module is done
	return false, true, nil
}

// NewSimpleCredentialsOwner creates a new SimpleCredentialsOwner.
func NewSimpleCredentialsOwner(credentials []SimpleCredential) *SimpleCredentialsOwner {
	return &SimpleCredentialsOwner{
		Credentials: credentials,
	}
}
