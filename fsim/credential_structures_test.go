package fsim

import (
	"testing"
)

func TestPasswordCredential(t *testing.T) {
	// Test valid PasswordCredential
	cred := PasswordCredential{
		Username:  "testuser",
		Password:  "testpass123",
		HashAlgo:  "bcrypt",
		Scope:     "sudoers",
		ExpiresAt: "2025-12-31T23:59:59Z",
	}

	if err := cred.Validate(); err != nil {
		t.Errorf("Valid PasswordCredential failed validation: %v", err)
	}

	// Test missing username
	cred.Username = ""
	if err := cred.Validate(); err == nil {
		t.Error("PasswordCredential with empty username should fail validation")
	}

	// Test missing password
	cred.Username = "testuser"
	cred.Password = ""
	if err := cred.Validate(); err == nil {
		t.Error("PasswordCredential with empty password should fail validation")
	}

	t.Log("PasswordCredential tests passed")
}

func TestSecretCredential(t *testing.T) {
	// Test valid SecretCredential
	cred := SecretCredential{
		ClientID: "test-client",
		Secret:   "super-secret-key",
		Type:     "api_key",
		Endpoint: "https://api.example.com",
	}

	if err := cred.Validate(); err != nil {
		t.Errorf("Valid SecretCredential failed validation: %v", err)
	}

	// Test missing secret
	cred.Secret = ""
	if err := cred.Validate(); err == nil {
		t.Error("SecretCredential with empty secret should fail validation")
	}

	// Test different secret types
	secretTypes := []string{"api_key", "oauth2_client_secret", "bootstrap_token", "bearer_token", "basic_auth"}
	for _, secretType := range secretTypes {
		cred.Secret = "test-secret"
		cred.Type = secretType
		if err := cred.Validate(); err != nil {
			t.Errorf("SecretCredential with type %s failed validation: %v", secretType, err)
		}
	}

	t.Log("SecretCredential tests passed")
}

func TestX509CertRequest(t *testing.T) {
	// Test valid X509CertRequest
	req := X509CertRequest{
		CSR: "-----BEGIN CERTIFICATE REQUEST-----\nMIIBVjCB...\n-----END CERTIFICATE REQUEST-----",
	}

	if err := req.Validate(); err != nil {
		t.Errorf("Valid X509CertRequest failed validation: %v", err)
	}

	// Test missing CSR
	req.CSR = ""
	if err := req.Validate(); err == nil {
		t.Error("X509CertRequest with empty CSR should fail validation")
	}

	t.Log("X509CertRequest tests passed")
}

func TestSSHPublicKey(t *testing.T) {
	// Test valid SSHPublicKey
	key := SSHPublicKey{
		PublicKey: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... test@example.com",
		Username:  "testuser",
		KeyType:   "rsa",
		Comment:   "Test SSH key",
	}

	if err := key.Validate(); err != nil {
		t.Errorf("Valid SSHPublicKey failed validation: %v", err)
	}

	// Test missing public key
	key.PublicKey = ""
	if err := key.Validate(); err == nil {
		t.Error("SSHPublicKey with empty public key should fail validation")
	}

	// Test different key types
	keyTypes := []string{"rsa", "ed25519", "ecdsa", "dsa"}
	for _, keyType := range keyTypes {
		key.PublicKey = "ssh-" + keyType + " AAAAB3NzaC1yc2EAAA... test@example.com"
		key.KeyType = keyType
		if err := key.Validate(); err != nil {
			t.Errorf("SSHPublicKey with key type %s failed validation: %v", keyType, err)
		}
	}

	t.Log("SSHPublicKey tests passed")
}
