// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"crypto/x509"
	"fmt"

	"github.com/fido-device-onboard/go-fdo/protocol"
)

// CertificateValidationErrorCode represents specific certificate validation failure reasons
type CertificateValidationErrorCode int

const (
	// CertValidationErrorUnknown - Unknown certificate validation error
	CertValidationErrorUnknown CertificateValidationErrorCode = iota

	// CertValidationErrorExpired - Certificate has expired
	CertValidationErrorExpired

	// CertValidationErrorNotYetValid - Certificate is not yet valid (NotBefore in future)
	CertValidationErrorNotYetValid

	// CertValidationErrorRevoked - Certificate has been revoked (via custom checker)
	CertValidationErrorRevoked

	// CertValidationErrorCustomCheck - Custom certificate checker failed (non-revocation)
	CertValidationErrorCustomCheck

	// CertValidationErrorSignature - Certificate signature verification failed
	CertValidationErrorSignature

	// CertValidationErrorKeyUsage - Certificate lacks required key usage
	CertValidationErrorKeyUsage

	// CertValidationErrorBasicConstraints - Certificate basic constraints invalid
	CertValidationErrorBasicConstraints

	// CertValidationErrorMissingPermission - Certificate missing required FDO permission OID
	CertValidationErrorMissingPermission

	// CertValidationErrorNotCA - Intermediate certificate is not a CA
	CertValidationErrorNotCA

	// CertValidationErrorChainHashMismatch - Certificate chain hash does not match voucher header
	CertValidationErrorChainHashMismatch
)

// String returns a human-readable description of the error code
func (c CertificateValidationErrorCode) String() string {
	switch c {
	case CertValidationErrorExpired:
		return "certificate expired"
	case CertValidationErrorNotYetValid:
		return "certificate not yet valid"
	case CertValidationErrorRevoked:
		return "certificate revoked"
	case CertValidationErrorCustomCheck:
		return "custom certificate validation failed"
	case CertValidationErrorSignature:
		return "certificate signature verification failed"
	case CertValidationErrorKeyUsage:
		return "certificate lacks required key usage"
	case CertValidationErrorBasicConstraints:
		return "certificate basic constraints invalid"
	case CertValidationErrorMissingPermission:
		return "certificate missing required FDO permission"
	case CertValidationErrorNotCA:
		return "intermediate certificate is not a CA"
	case CertValidationErrorChainHashMismatch:
		return "certificate chain hash mismatch"
	default:
		return "unknown certificate validation error"
	}
}

// CertificateValidationError represents a detailed certificate validation error
type CertificateValidationError struct {
	Code        CertificateValidationErrorCode
	Certificate *x509.Certificate // The certificate that failed validation
	Message     string            // Additional details about the failure
	Context     string            // Where the error occurred (e.g., "delegate chain", "OV device cert chain")
}

// Error implements the error interface
func (e *CertificateValidationError) Error() string {
	if e.Certificate != nil {
		return fmt.Sprintf("%s validation failed for %s: %s", e.Context, e.Certificate.Subject, e.Message)
	}
	return fmt.Sprintf("%s validation failed: %s", e.Context, e.Message)
}

// ToProtocolErrorMessage converts the certificate validation error to an FDO protocol error message
func (e *CertificateValidationError) ToProtocolErrorMessage() protocol.ErrorMessage {
	errorString := fmt.Sprintf("Certificate validation failed: %s", e.Code.String())
	if e.Certificate != nil {
		errorString += fmt.Sprintf(" (subject: %s)", e.Certificate.Subject)
	}

	return protocol.ErrorMessage{
		Code:      protocol.InvalidMessageErrCode,
		ErrString: errorString,
	}
}

// NewCertificateValidationError creates a new certificate validation error
func NewCertificateValidationError(code CertificateValidationErrorCode, cert *x509.Certificate, context, message string) *CertificateValidationError {
	return &CertificateValidationError{
		Code:        code,
		Certificate: cert,
		Message:     message,
		Context:     context,
	}
}

// EnhancedCertificateChecker extends the CertificateChecker interface to provide detailed error information
type EnhancedCertificateChecker interface {
	// CheckCertificate performs custom validation on a certificate
	// Returns a CertificateValidationError for detailed failure information
	CheckCertificate(cert *x509.Certificate) *CertificateValidationError
}

// LegacyCertificateCheckerAdapter wraps old CertificateChecker implementations
type LegacyCertificateCheckerAdapter struct {
	checker interface {
		CheckCertificate(cert *x509.Certificate) error
	}
}

// CheckCertificate wraps legacy certificate checker and converts errors to CertificateValidationError
func (l *LegacyCertificateCheckerAdapter) CheckCertificate(cert *x509.Certificate) *CertificateValidationError {
	if err := l.checker.CheckCertificate(cert); err != nil {
		// Try to determine if this is a revocation error based on error message
		if isRevocationError(err) {
			return NewCertificateValidationError(
				CertValidationErrorRevoked,
				cert,
				"custom certificate check",
				err.Error(),
			)
		}
		return NewCertificateValidationError(
			CertValidationErrorCustomCheck,
			cert,
			"custom certificate check",
			err.Error(),
		)
	}
	return nil
}

func isRevocationError(err error) bool {
	errStr := err.Error()
	revocationIndicators := []string{
		"revoked", "ocsp", "crl", "revocation",
	}
	for _, indicator := range revocationIndicators {
		if contains(errStr, indicator) {
			return true
		}
	}
	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > len(substr) &&
			(s[:len(substr)] == substr ||
				s[len(s)-len(substr):] == substr ||
				findSubstring(s, substr))))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
