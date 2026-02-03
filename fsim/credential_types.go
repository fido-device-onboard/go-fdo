// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

// Credential type identifiers for all credential flows
// These correspond to the unified enumeration in fdo.credentials.md
const (
	// Provisioned Credentials
	CredentialTypePassword = 1 // PasswordCredential structure
	CredentialTypeSecret   = 2 // SecretCredential structure (unified secrets)

	// Enrolled Credentials
	CredentialTypeX509Cert           = 3 // X509CertRequest/Response structures
	CredentialTypeServerGeneratedKey = 4 // ServerKeyRequest/Response structures

	// Registered Credentials
	CredentialTypeSSHPublicKey = 5 // SSHPublicKey structure
)

// CredentialTypeNames maps credential type IDs to human-readable names
var CredentialTypeNames = map[int]string{
	CredentialTypePassword:           "password",
	CredentialTypeSecret:             "secret",
	CredentialTypeX509Cert:           "x509_cert",
	CredentialTypeServerGeneratedKey: "server_generated_key",
	CredentialTypeSSHPublicKey:       "ssh_public_key",
}

// IsValidCredentialType checks if a credential type ID is valid
func IsValidCredentialType(credentialType int) bool {
	_, exists := CredentialTypeNames[credentialType]
	return exists
}

// CredentialTypeFlow maps credential types to their protocol flow
var CredentialTypeFlow = map[int]string{
	CredentialTypePassword:           "provisioned",
	CredentialTypeSecret:             "provisioned",
	CredentialTypeX509Cert:           "enrolled",
	CredentialTypeServerGeneratedKey: "enrolled",
	CredentialTypeSSHPublicKey:       "registered",
}
