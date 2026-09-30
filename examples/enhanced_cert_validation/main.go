// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package main demonstrates enhanced certificate validation with detailed error reporting.
// This example shows how to use the EnhancedCertificateChecker interface to implement
// OCSP/CRL checking and custom policy validation with proper error bubbling.
package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"time"

	"github.com/fido-device-onboard/go-fdo"
)

// EnhancedOCSPChecker demonstrates the new EnhancedCertificateChecker interface
type EnhancedOCSPChecker struct {
	ocspServers []string
	crlCache    map[string][]byte // Store CRL data as bytes
}

func (e *EnhancedOCSPChecker) CheckCertificate(cert *x509.Certificate) *fdo.CertificateValidationError {
	// Example 1: Check OCSP
	if len(cert.OCSPServer) > 0 {
		// Perform OCSP checking (simplified example)
		if revoked, err := e.checkOCSP(cert); err != nil {
			return fdo.NewCertificateValidationError(
				fdo.CertValidationErrorCustomCheck,
				cert,
				"OCSP verification",
				fmt.Sprintf("OCSP check failed: %v", err),
			)
		} else if revoked {
			return fdo.NewCertificateValidationError(
				fdo.CertValidationErrorRevoked,
				cert,
				"OCSP verification",
				"certificate revoked via OCSP",
			)
		}
	}

	// Example 2: Check CRL
	if len(cert.CRLDistributionPoints) > 0 {
		if revoked, err := e.checkCRL(cert); err != nil {
			return fdo.NewCertificateValidationError(
				fdo.CertValidationErrorCustomCheck,
				cert,
				"CRL verification",
				fmt.Sprintf("CRL check failed: %v", err),
			)
		} else if revoked {
			return fdo.NewCertificateValidationError(
				fdo.CertValidationErrorRevoked,
				cert,
				"CRL verification",
				"certificate revoked via CRL",
			)
		}
	}

	// Example 3: Custom policy checks
	if cert.Subject.CommonName == "blacklisted-device" {
		return fdo.NewCertificateValidationError(
			fdo.CertValidationErrorCustomCheck,
			cert,
			"policy validation",
			"device certificate is on blacklist",
		)
	}

	// Certificate is valid
	return nil
}

func (e *EnhancedOCSPChecker) checkOCSP(cert *x509.Certificate) (bool, error) {
	// Simplified OCSP checking - in reality, you'd use golang.org/x/crypto/ocsp
	slog.Info("Checking OCSP", "cert", cert.Subject, "servers", cert.OCSPServer)
	// Return false for "not revoked", nil for success
	return false, nil
}

func (e *EnhancedOCSPChecker) checkCRL(cert *x509.Certificate) (bool, error) {
	// Simplified CRL checking
	slog.Info("Checking CRL", "cert", cert.Subject, "distribution_points", cert.CRLDistributionPoints)
	// Return false for "not revoked", nil for success
	return false, nil
}

// LegacyRevocationChecker demonstrates backward compatibility with old CertificateChecker interface
type LegacyRevocationChecker struct{}

func (l *LegacyRevocationChecker) CheckCertificate(cert *x509.Certificate) error {
	// Example: Simple expiration check (legacy interface)
	if time.Now().After(cert.NotAfter) {
		return fmt.Errorf("certificate expired")
	}
	return nil
}

func main() {
	// Example 1: Create enhanced certificate checker
	slog.Info("Creating enhanced certificate checker with OCSP/CRL support")
	enhancedChecker := &EnhancedOCSPChecker{
		ocspServers: []string{"http://ocsp.example.com"},
		crlCache:    make(map[string][]byte),
	}

	// Note: Enhanced checker cannot be set directly due to interface incompatibility
	// In practice, you would need to modify SetCertificateChecker to accept EnhancedCertificateChecker
	// or use a wrapper approach

	// Example 2: Use legacy certificate checker (will be automatically wrapped)
	slog.Info("Configuring legacy certificate checker")
	legacyChecker := &LegacyRevocationChecker{}
	fdo.SetCertificateChecker(legacyChecker)

	// Example 3: Simulate certificate validation errors with an expired certificate
	cert := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "expired-device"},
		NotAfter: time.Now().Add(-24 * time.Hour), // Expired yesterday
	}

	// This would be called internally during FDO protocol execution
	// if using the enhanced checker:
	if err := enhancedChecker.CheckCertificate(cert); err != nil {
		slog.Error("Certificate validation failed",
			"error_code", err.Code,
			"error_type", err.Code.String(),
			"cert_subject", err.Certificate.Subject,
			"context", err.Context,
			"message", err.Message,
		)

		// Convert to protocol error message for client
		protocolMsg := err.ToProtocolErrorMessage()
		slog.Info("Protocol error message for client",
			"code", protocolMsg.Code,
			"error_string", protocolMsg.ErrString,
		)
	}

	// Example 4: Test with a blacklisted certificate to show custom policy errors
	blacklistedCert := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "blacklisted-device"},
		NotAfter: time.Now().Add(24 * time.Hour), // Valid but blacklisted
	}

	if err := enhancedChecker.CheckCertificate(blacklistedCert); err != nil {
		slog.Error("Blacklisted certificate validation failed",
			"error_code", err.Code,
			"error_type", err.Code.String(),
			"cert_subject", err.Certificate.Subject,
			"context", err.Context,
			"message", err.Message,
		)

		// Convert to protocol error message for client
		protocolMsg := err.ToProtocolErrorMessage()
		slog.Info("Protocol error message for blacklisted cert",
			"code", protocolMsg.Code,
			"error_string", protocolMsg.ErrString,
		)
	} else {
		slog.Info("Blacklisted certificate unexpectedly passed validation")
	}
}
