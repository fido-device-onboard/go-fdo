// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"context"
	"testing"

	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

func TestCredentialsOwnerBasic(t *testing.T) {
	// Test that CredentialsOwner can be created and implements the interface
	creds := []ProvisionedCredential{
		{
			CredentialID:   "test-id",
			CredentialType: "password",
			CredentialData: []byte("test-password"),
			Metadata:       map[string]any{"username": "testuser"},
			HashAlg:        "sha256",
			EndpointURL:    "https://api.example.com/v1",
		},
	}

	owner := NewCredentialsOwner(creds)
	if owner == nil {
		t.Fatal("NewCredentialsOwner returned nil")
	}

	// Verify it implements OwnerModule interface
	var _ serviceinfo.OwnerModule = owner

	// Test ProduceInfo doesn't panic
	producer := &serviceinfo.Producer{}
	ctx := context.Background()
	_, _, err := owner.ProduceInfo(ctx, producer)
	if err != nil {
		t.Logf("ProduceInfo error (expected without full setup): %v", err)
	}
}

func TestCredentialsDeviceBasic(t *testing.T) {
	// Test that CredentialsDevice can be created and implements the interface
	device := NewCredentialsDevice(func(credentialID, credentialType string, data []byte, metadata map[string]any) error {
		t.Logf("Received credential: %s (%s)", credentialID, credentialType)
		return nil
	})

	if device == nil {
		t.Fatal("NewCredentialsDevice returned nil")
	}

	// Verify it implements DeviceModule interface
	var _ serviceinfo.DeviceModule = device
}
