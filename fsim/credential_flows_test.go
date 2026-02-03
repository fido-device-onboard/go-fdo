package fsim

import (
	"testing"
)

func TestCredentialFlowsBasic(t *testing.T) {
	// Test basic credential flow setup

	// Test device creation with callback
	device := NewCredentialsDevice(func(credentialID string, credentialType int, data []byte, metadata map[string]any) error {
		t.Logf("Device received credential: ID=%s, Type=%d, Size=%d", credentialID, credentialType, len(data))

		// Verify credential type is valid
		if !IsValidCredentialType(credentialType) {
			t.Errorf("Invalid credential type: %d", credentialType)
		}

		return nil
	})

	if device == nil {
		t.Fatal("Failed to create CredentialsDevice")
	}

	// Test owner creation with callbacks
	owner := &CredentialsOwner{
		OnPublicKeyReceived: func(credentialID string, credentialType int, publicKey []byte, metadata map[string]any) error {
			t.Logf("Owner received public key: ID=%s, Type=%d, Size=%d", credentialID, credentialType, len(publicKey))

			if !IsValidCredentialType(credentialType) {
				t.Errorf("Invalid credential type: %d", credentialType)
			}

			return nil
		},
		OnEnrollmentRequest: func(credentialID string, credentialType int, requestData []byte, metadata map[string]any) (responseData []byte, responseMetadata map[string]any, err error) {
			t.Logf("Owner received enrollment request: ID=%s, Type=%d, Size=%d", credentialID, credentialType, len(requestData))

			if !IsValidCredentialType(credentialType) {
				t.Errorf("Invalid credential type: %d", credentialType)
			}

			// Mock response
			responseData = []byte("mock-certificate")
			responseMetadata = map[string]any{"format": "pem"}

			return responseData, responseMetadata, nil
		},
	}

	// Test basic module functionality
	if err := device.Transition(true); err != nil {
		t.Errorf("Device transition failed: %v", err)
	}

	if err := owner.Transition(true); err != nil {
		t.Errorf("Owner transition failed: %v", err)
	}

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

	// Test validation
	if !IsValidCredentialType(CredentialTypePassword) {
		t.Error("CredentialTypePassword should be valid")
	}
	if IsValidCredentialType(99) {
		t.Error("Invalid credential type 99 should not be valid")
	}

	t.Log("Basic credential flows test passed")
}

func TestCredentialTypeConstants(t *testing.T) {
	// Test all credential type constants and mappings

	// Test constants
	expectedConstants := map[int]string{
		CredentialTypePassword:     "password",
		CredentialTypeSecret:       "secret",
		CredentialTypeX509Cert:     "x509_cert",
		CredentialTypeSSHPublicKey: "ssh_public_key",
	}

	for credType, expectedName := range expectedConstants {
		if CredentialTypeNames[credType] != expectedName {
			t.Errorf("Credential type %d should have name '%s', got '%s'", credType, expectedName, CredentialTypeNames[credType])
		}
	}

	// Test flows
	expectedFlows := map[int]string{
		CredentialTypePassword:     "provisioned",
		CredentialTypeSecret:       "provisioned",
		CredentialTypeX509Cert:     "enrolled",
		CredentialTypeSSHPublicKey: "registered",
	}

	for credType, expectedFlow := range expectedFlows {
		if CredentialTypeFlow[credType] != expectedFlow {
			t.Errorf("Credential type %d should have flow '%s', got '%s'", credType, expectedFlow, CredentialTypeFlow[credType])
		}
	}

	t.Log("Credential type constants test passed")
}
