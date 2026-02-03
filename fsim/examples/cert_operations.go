// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

// Package examples provides example implementations of FSIM callbacks for real-world systems.
// These implementations are NOT part of the core library and should be adapted for your environment.
package examples

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// SimpleCertificateAuthority provides a basic CA implementation for the CSR FSIM.
// This is an EXAMPLE implementation showing certificate operations.
// For production, use a proper PKI solution (HashiCorp Vault, EJBCA, etc.).
type SimpleCertificateAuthority struct {
	// CAKeyPath is the path to the CA private key (PEM format)
	CAKeyPath string

	// CACertPath is the path to the CA certificate (PEM format)
	CACertPath string

	// CertStorePath is where issued certificates are stored
	CertStorePath string

	// ValidityDays is the validity period for issued certificates
	ValidityDays int

	// Internal cache
	caKey  crypto.PrivateKey
	caCert *x509.Certificate
}

// Initialize loads the CA key and certificate.
func (ca *SimpleCertificateAuthority) Initialize() error {
	// Load CA private key
	keyData, err := os.ReadFile(ca.CAKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read CA key: %w", err)
	}

	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode CA key PEM")
	}

	// Try parsing as different key types
	if key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err == nil {
		ca.caKey = key
	} else if key, err := x509.ParseECPrivateKey(keyBlock.Bytes); err == nil {
		ca.caKey = key
	} else if key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err == nil {
		ca.caKey = key
	} else {
		return fmt.Errorf("failed to parse CA private key")
	}

	// Load CA certificate
	certData, err := os.ReadFile(ca.CACertPath)
	if err != nil {
		return fmt.Errorf("failed to read CA cert: %w", err)
	}

	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return fmt.Errorf("failed to decode CA cert PEM")
	}

	ca.caCert, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Create cert store directory if needed
	if ca.CertStorePath != "" {
		if err := os.MkdirAll(ca.CertStorePath, 0750); err != nil {
			return fmt.Errorf("failed to create cert store: %w", err)
		}
	}

	// Set default validity if not specified
	if ca.ValidityDays == 0 {
		ca.ValidityDays = 365
	}

	return nil
}

// SignCSR signs a Certificate Signing Request and returns the signed certificate.
// This is used as the EnrollmentHandler callback for CSROwner.
func (ca *SimpleCertificateAuthority) SignCSR(csrDER []byte) ([]byte, error) {
	// Parse CSR
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	// Verify CSR signature
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csr.Subject,
		NotBefore:    now,
		NotAfter:     now.AddDate(0, 0, ca.ValidityDays),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
	}

	// Sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.caCert, csr.PublicKey, ca.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	// Store the certificate if path is configured
	if ca.CertStorePath != "" {
		certPath := filepath.Join(ca.CertStorePath, fmt.Sprintf("%s.crt", serialNumber.Text(16)))
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
			// Log but don't fail
			fmt.Printf("Warning: failed to store certificate: %v\n", err)
		}
	}

	return certDER, nil
}

// GetCACertificates returns the CA certificate chain.
// This is used as the CACertsHandler callback for CSROwner.
func (ca *SimpleCertificateAuthority) GetCACertificates() ([][]byte, error) {
	if ca.caCert == nil {
		return nil, fmt.Errorf("CA not initialized")
	}

	// Return just the CA cert (in production, return full chain)
	return [][]byte{ca.caCert.Raw}, nil
}

// GenerateServerKey generates a key pair on the server side.
// This is used as the ServerKeygenHandler callback for CSROwner.
func (ca *SimpleCertificateAuthority) GenerateServerKey(keyType string, subject pkix.Name) (certDER []byte, keyDER []byte, err error) {
	var privateKey crypto.PrivateKey
	var publicKey crypto.PublicKey

	// Generate key pair based on type
	switch keyType {
	case "rsa", "rsa-2048":
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
		}
		privateKey = key
		publicKey = &key.PublicKey

	case "rsa-4096":
		key, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
		}
		privateKey = key
		publicKey = &key.PublicKey

	case "ecdsa", "ecdsa-p256":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
		}
		privateKey = key
		publicKey = &key.PublicKey

	case "ecdsa-p384":
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
		}
		privateKey = key
		publicKey = &key.PublicKey

	default:
		return nil, nil, fmt.Errorf("unsupported key type: %s", keyType)
	}

	// Create certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    now,
		NotAfter:     now.AddDate(0, 0, ca.ValidityDays),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	// Sign the certificate
	certDER, err = x509.CreateCertificate(rand.Reader, template, ca.caCert, publicKey, ca.caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	// Marshal private key to PKCS#8
	keyDER, err = x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Store the certificate if path is configured
	if ca.CertStorePath != "" {
		certPath := filepath.Join(ca.CertStorePath, fmt.Sprintf("%s.crt", serialNumber.Text(16)))
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
			fmt.Printf("Warning: failed to store certificate: %v\n", err)
		}
	}

	return certDER, keyDER, nil
}

// GetCSRAttributes returns CSR attributes for the device.
// This is used as the CSRAttributesHandler callback for CSROwner.
func (ca *SimpleCertificateAuthority) GetCSRAttributes() ([]byte, error) {
	// Return empty attributes (device can use any attributes)
	// In production, you might specify required attributes
	return []byte{}, nil
}

// DeviceCertificateStore provides certificate storage for the device side.
// This is an EXAMPLE implementation for storing device certificates.
type DeviceCertificateStore struct {
	// CertPath is where the device certificate is stored
	CertPath string

	// KeyPath is where the device private key is stored
	KeyPath string

	// CAPath is where CA certificates are stored
	CAPath string
}

// InstallCertificate stores a certificate and private key on the device.
// This is used as the InstallCertificate callback for CSRDevice.
func (store *DeviceCertificateStore) InstallCertificate(certDER, keyDER []byte) error {
	// Ensure directories exist
	if err := os.MkdirAll(filepath.Dir(store.CertPath), 0750); err != nil {
		return fmt.Errorf("failed to create cert directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(store.KeyPath), 0750); err != nil {
		return fmt.Errorf("failed to create key directory: %w", err)
	}

	// Write certificate
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(store.CertPath, certPEM, 0600); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Write private key (if provided)
	if keyDER != nil {
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		if err := os.WriteFile(store.KeyPath, keyPEM, 0600); err != nil {
			return fmt.Errorf("failed to write private key: %w", err)
		}
	}

	return nil
}

// GetExistingCertificate retrieves the current device certificate.
// This is used as the GetExistingCertificate callback for CSRDevice.
func (store *DeviceCertificateStore) GetExistingCertificate() ([]byte, error) {
	// Read certificate file
	certPEM, err := os.ReadFile(store.CertPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No existing certificate
		}
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	// Decode PEM
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}

	return block.Bytes, nil
}

// InstallCACertificates stores CA certificates on the device.
// This is used as the InstallCACertificates callback for CSRDevice.
func (store *DeviceCertificateStore) InstallCACertificates(caCertsDER [][]byte) error {
	if store.CAPath == "" {
		return fmt.Errorf("CA path not configured")
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(store.CAPath), 0750); err != nil {
		return fmt.Errorf("failed to create CA directory: %w", err)
	}

	// Write all CA certificates to a single file
	var allPEM []byte
	for i, certDER := range caCertsDER {
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		allPEM = append(allPEM, certPEM...)

		// Also write individual files for reference
		individualPath := filepath.Join(filepath.Dir(store.CAPath), fmt.Sprintf("ca-%d.crt", i))
		if err := os.WriteFile(individualPath, certPEM, 0600); err != nil {
			fmt.Printf("Warning: failed to write individual CA cert: %v\n", err)
		}
	}

	// Write combined CA bundle
	if err := os.WriteFile(store.CAPath, allPEM, 0600); err != nil {
		return fmt.Errorf("failed to write CA bundle: %w", err)
	}

	return nil
}

// DeviceKeyGenerator provides key generation for the device side.
// This is an EXAMPLE implementation for generating device key pairs.
type DeviceKeyGenerator struct{}

// GenerateKeyPair generates a key pair for CSR creation.
// This is used as the GenerateKeyPair callback for CSRDevice.
func (gen *DeviceKeyGenerator) GenerateKeyPair(keyType string) (crypto.PrivateKey, error) {
	switch keyType {
	case "rsa", "rsa-2048":
		return rsa.GenerateKey(rand.Reader, 2048)

	case "rsa-4096":
		return rsa.GenerateKey(rand.Reader, 4096)

	case "ecdsa", "ecdsa-p256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	case "ecdsa-p384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// CreateSelfSignedCA creates a self-signed CA certificate and key.
// This is a utility function for setting up a test CA.
func CreateSelfSignedCA(keyPath, certPath string) error {
	// Generate CA key
	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Create CA certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Example CA",
			Organization: []string{"Example Organization"},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(10, 0, 0), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	// Self-sign the certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Write CA key
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caKey),
	})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write CA key: %w", err)
	}

	// Write CA certificate
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		return fmt.Errorf("failed to write CA certificate: %w", err)
	}

	return nil
}
