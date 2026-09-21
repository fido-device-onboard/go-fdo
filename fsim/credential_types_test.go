// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"testing"
)

func TestCredentialTypes(t *testing.T) {
	// Test credential type constants
	if CredentialTypePassword != 1 {
		t.Errorf("Expected CredentialTypePassword = 1, got %d", CredentialTypePassword)
	}
	if CredentialTypeSecret != 2 {
		t.Errorf("Expected CredentialTypeSecret = 2, got %d", CredentialTypeSecret)
	}
	if CredentialTypeX509Cert != 3 {
		t.Errorf("Expected CredentialTypeX509Cert = 3, got %d", CredentialTypeX509Cert)
	}
	if CredentialTypeSSHPublicKey != 5 {
		t.Errorf("Expected CredentialTypeSSHPublicKey = 5, got %d", CredentialTypeSSHPublicKey)
	}

	// Test credential type validation
	if !IsValidCredentialType(CredentialTypePassword) {
		t.Error("CredentialTypePassword should be valid")
	}
	if !IsValidCredentialType(CredentialTypeSecret) {
		t.Error("CredentialTypeSecret should be valid")
	}
	if IsValidCredentialType(99) {
		t.Error("Invalid credential type 99 should not be valid")
	}

	// Test credential type names
	if CredentialTypeNames[CredentialTypePassword] != "password" {
		t.Errorf("Expected password, got %s", CredentialTypeNames[CredentialTypePassword])
	}
	if CredentialTypeNames[CredentialTypeSecret] != "secret" {
		t.Errorf("Expected secret, got %s", CredentialTypeNames[CredentialTypeSecret])
	}

	// Test credential type flows
	if CredentialTypeFlow[CredentialTypePassword] != "provisioned" {
		t.Errorf("Expected provisioned, got %s", CredentialTypeFlow[CredentialTypePassword])
	}
	if CredentialTypeFlow[CredentialTypeSSHPublicKey] != "registered" {
		t.Errorf("Expected registered, got %s", CredentialTypeFlow[CredentialTypeSSHPublicKey])
	}

	t.Log("All credential type tests passed")
}
