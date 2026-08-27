// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/fido-device-onboard/go-fdo/v2/protocol"
)

// CertificateValidationErrorCode represents specific certificate validation failure reasons.
type CertificateValidationErrorCode int

// Certificate validation error codes.
const (
	CertValidationErrorUnknown CertificateValidationErrorCode = iota
	CertValidationErrorExpired
	CertValidationErrorNotYetValid
	CertValidationErrorRevoked
	CertValidationErrorCustomCheck
	CertValidationErrorSignature
	CertValidationErrorKeyUsage
	CertValidationErrorBasicConstraints
	CertValidationErrorMissingPermission
	CertValidationErrorNotCA
	CertValidationErrorChainHashMismatch
)

// String returns a human-readable description of the error code.
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

// CertificateValidationError represents a detailed certificate validation error.
type CertificateValidationError struct {
	Code        CertificateValidationErrorCode
	Certificate *x509.Certificate
	Message     string
	Context     string
}

// Error implements the error interface.
func (e *CertificateValidationError) Error() string {
	if e.Certificate != nil {
		return fmt.Sprintf("%s validation failed for %s: %s", e.Context, e.Certificate.Subject, e.Message)
	}
	return fmt.Sprintf("%s validation failed: %s", e.Context, e.Message)
}

// ToProtocolErrorMessage converts the certificate validation error to an FDO protocol error message.
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

// NewCertificateValidationError creates a new certificate validation error.
func NewCertificateValidationError(code CertificateValidationErrorCode, cert *x509.Certificate, context, message string) *CertificateValidationError {
	return &CertificateValidationError{
		Code:        code,
		Certificate: cert,
		Message:     message,
		Context:     context,
	}
}

func isRevocationError(err error) bool {
	errStr := strings.ToLower(err.Error())
	for _, indicator := range []string{"revoked", "ocsp", "crl", "revocation"} {
		if strings.Contains(errStr, indicator) {
			return true
		}
	}
	return false
}
