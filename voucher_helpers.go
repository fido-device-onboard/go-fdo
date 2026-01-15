// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"crypto/x509"
	"fmt"
	"reflect"
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

// callCertificateChecker calls the certificate checker using reflection to support both interfaces
func callCertificateChecker(cert *x509.Certificate) *CertificateValidationError {
	checkerVal := reflect.ValueOf(certificateChecker)
	if !checkerVal.IsValid() {
		return nil
	}

	method := checkerVal.MethodByName("CheckCertificate")
	if !method.IsValid() {
		return nil
	}

	methodType := method.Type()
	// Check if the method returns *CertificateValidationError (enhanced interface)
	if methodType.NumOut() == 1 && methodType.Out(0) == reflect.TypeOf((*CertificateValidationError)(nil)).Elem() {
		return callEnhancedChecker(method, cert)
	}
	// Otherwise it's a legacy checker returning error
	return callLegacyChecker(method, cert)
}

// callEnhancedChecker calls an enhanced certificate checker
func callEnhancedChecker(method reflect.Value, cert *x509.Certificate) *CertificateValidationError {
	result := method.Call([]reflect.Value{reflect.ValueOf(cert)})
	if len(result) == 1 && !result[0].IsNil() {
		return result[0].Interface().(*CertificateValidationError)
	}
	return nil
}

// callLegacyChecker calls a legacy certificate checker and wraps the error
func callLegacyChecker(method reflect.Value, cert *x509.Certificate) *CertificateValidationError {
	result := method.Call([]reflect.Value{reflect.ValueOf(cert)})
	if len(result) != 1 || result[0].IsNil() {
		return nil
	}

	err, ok := result[0].Interface().(error)
	if !ok {
		return nil
	}

	// Wrap legacy error
	if isRevocationError(err) {
		return NewCertificateValidationError(
			CertValidationErrorRevoked,
			cert,
			"certificate chain",
			err.Error(),
		)
	}
	return NewCertificateValidationError(
		CertValidationErrorCustomCheck,
		cert,
		"certificate chain",
		err.Error(),
	)
}
