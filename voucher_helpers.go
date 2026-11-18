// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"crypto/x509"
	"fmt"
	"time"
)

// checkCertificateValidity checks if a certificate is within its validity period
func checkCertificateValidity(cert *x509.Certificate, index int) error {
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return NewCertificateValidationError(
			CertValidationErrorNotYetValid,
			cert,
			"certificate chain",
			fmt.Sprintf("certificate %d not yet valid (NotBefore: %v)", index, cert.NotBefore),
		)
	}
	if now.After(cert.NotAfter) {
		return NewCertificateValidationError(
			CertValidationErrorExpired,
			cert,
			"certificate chain",
			fmt.Sprintf("certificate %d expired (NotAfter: %v)", index, cert.NotAfter),
		)
	}
	return nil
}

// runCustomCertificateChecker runs the custom certificate checker if configured
func runCustomCertificateChecker(cert *x509.Certificate) error {
	if certificateChecker == nil {
		return nil
	}

	certErr := callCertificateChecker(cert)
	if certErr != nil {
		certErr.Context = "certificate chain"
		return certErr
	}
	return nil
}

// callCertificateChecker calls the configured certificate checker and wraps
// any error it returns as a CertificateValidationError.
func callCertificateChecker(cert *x509.Certificate) *CertificateValidationError {
	err := certificateChecker.CheckCertificate(cert)
	if err == nil {
		return nil
	}
	code := CertValidationErrorCustomCheck
	if isRevocationError(err) {
		code = CertValidationErrorRevoked
	}
	return NewCertificateValidationError(code, cert, "certificate chain", err.Error())
}
