// SPDX-FileCopyrightText: (C) 2024 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"strings"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// CSR implements the fdo.csr FSIM for certificate enrollment on the device side.
// See https://github.com/fido-alliance/fdo-sim/blob/main/fsim-repository/fdo.csr.md
type CSR struct {
	// GenerateKey generates a new private key for certificate enrollment.
	// If nil, the device will request server-side key generation.
	GenerateKey func() (crypto.Signer, error)

	// CreateCSR creates a certificate signing request with the given subject and key.
	// If nil, a default implementation using x509.CreateCertificateRequest is used.
	CreateCSR func(subject pkix.Name, key crypto.Signer) ([]byte, error)

	// InstallCertificate is called when a certificate is received from the owner.
	// The implementation should store the certificate appropriately.
	InstallCertificate func(cert *x509.Certificate) error

	// InstallPrivateKey is called when a private key is received (server-side keygen).
	// The implementation should store the private key securely.
	InstallPrivateKey func(key crypto.PrivateKey) error

	// InstallCACerts is called when CA certificates are received.
	// The implementation should update trust anchors.
	InstallCACerts func(certs []*x509.Certificate) error

	// Subject defines the certificate subject for enrollment requests.
	// This is used when generating CSRs.
	Subject pkix.Name

	// ExistingCert is the current certificate for re-enrollment.
	// If set, simplereenroll will be used instead of simpleenroll.
	ExistingCert *x509.Certificate

	// ExistingKey is the private key for the existing certificate.
	// Required for re-enrollment to sign the CSR.
	ExistingKey crypto.Signer

	// RequestCSRAttrs determines whether to request CSR attributes from the CA.
	RequestCSRAttrs bool

	// Internal state
	operation    string // Current operation: "cacerts", "enroll", "reenroll", "serverkeygen"
	privateKey   crypto.Signer
	csrAttrs     []byte
	pendingError *uint
}

var _ serviceinfo.DeviceModule = (*CSR)(nil)

// Transition implements serviceinfo.DeviceModule.
func (c *CSR) Transition(active bool) error {
	if !active {
		c.reset()
	}
	return nil
}

// Receive implements serviceinfo.DeviceModule.
func (c *CSR) Receive(ctx context.Context, messageName string, messageBody io.Reader, respond func(string) io.Writer, yield func()) error {
	if err := c.receive(ctx, messageName, messageBody, respond, yield); err != nil {
		c.reset()
		return err
	}
	return nil
}

func (c *CSR) receive(ctx context.Context, messageName string, messageBody io.Reader, respond func(string) io.Writer, yield func()) error {
	switch messageName {
	case "cacerts-res":
		return c.receiveCACerts(messageBody)

	case "simpleenroll-res":
		return c.receiveEnrollment(messageBody)

	case "simplereenroll-res":
		return c.receiveReenrollment(messageBody)

	case "serverkeygen-res":
		return c.receiveServerKeygen(messageBody)

	case "csrattrs-res":
		return c.receiveCSRAttrs(messageBody)

	case "error":
		var errCode uint
		if err := cbor.NewDecoder(messageBody).Decode(&errCode); err != nil {
			return fmt.Errorf("error decoding error code: %w", err)
		}
		c.pendingError = &errCode
		return fmt.Errorf("CSR operation failed with error code %d: %s", errCode, csrErrorString(errCode))

	default:
		return fmt.Errorf("unknown message %s", messageName)
	}
}

// Yield implements serviceinfo.DeviceModule.
func (c *CSR) Yield(ctx context.Context, respond func(message string) io.Writer, yield func()) error {
	// Check for pending error
	if c.pendingError != nil {
		return fmt.Errorf("CSR operation failed with error code %d", *c.pendingError)
	}

	// No automatic yielding - operations are initiated by the application
	return nil
}

// RequestCACerts requests CA certificates from the owner.
// format should be 281 for "application/pkcs7-mime; smime-type=certs-only"
// or 287 for "application/pkix-cert".
func (c *CSR) RequestCACerts(ctx context.Context, format uint, respond func(string) io.Writer, yield func()) error {
	c.operation = "cacerts"
	if err := cbor.NewEncoder(respond("cacerts-req")).Encode(format); err != nil {
		return fmt.Errorf("error sending cacerts-req: %w", err)
	}
	yield()
	return nil
}

// Enroll performs certificate enrollment (simpleenroll or simplereenroll).
func (c *CSR) Enroll(ctx context.Context, respond func(string) io.Writer, yield func()) error {
	// Determine if this is enrollment or re-enrollment
	isReenroll := c.ExistingCert != nil && c.ExistingKey != nil

	// Generate or use existing key
	var key crypto.Signer
	var err error
	if isReenroll {
		key = c.ExistingKey
	} else if c.GenerateKey != nil {
		key, err = c.GenerateKey()
		if err != nil {
			return fmt.Errorf("error generating key: %w", err)
		}
		c.privateKey = key
	} else {
		// Request server-side key generation
		return c.RequestServerKeygen(ctx, respond, yield)
	}

	// Create CSR
	csrDER, err := c.createCSR(key)
	if err != nil {
		return fmt.Errorf("error creating CSR: %w", err)
	}

	// Send appropriate request
	if isReenroll {
		c.operation = "reenroll"
		if err := cbor.NewEncoder(respond("simplereenroll-req")).Encode(base64.StdEncoding.EncodeToString(csrDER)); err != nil {
			return fmt.Errorf("error sending simplereenroll-req: %w", err)
		}
	} else {
		c.operation = "enroll"
		if err := cbor.NewEncoder(respond("simpleenroll-req")).Encode(base64.StdEncoding.EncodeToString(csrDER)); err != nil {
			return fmt.Errorf("error sending simpleenroll-req: %w", err)
		}
	}

	yield()
	return nil
}

// RequestServerKeygen requests server-side key generation.
func (c *CSR) RequestServerKeygen(ctx context.Context, respond func(string) io.Writer, yield func()) error {
	c.operation = "serverkeygen"

	// Create a dummy CSR (public key and signature will be ignored by server)
	// Generate a temporary key just for the CSR structure
	tempKey, err := c.GenerateKey()
	if err != nil {
		return fmt.Errorf("error generating temporary key for serverkeygen CSR: %w", err)
	}

	csrDER, err := c.createCSR(tempKey)
	if err != nil {
		return fmt.Errorf("error creating serverkeygen CSR: %w", err)
	}

	if err := cbor.NewEncoder(respond("serverkeygen-req")).Encode(base64.StdEncoding.EncodeToString(csrDER)); err != nil {
		return fmt.Errorf("error sending serverkeygen-req: %w", err)
	}

	yield()
	return nil
}

// RequestCSRAttributes requests CSR attributes from the CA.
func (c *CSR) RequestCSRAttributes(ctx context.Context, respond func(string) io.Writer, yield func()) error {
	c.operation = "csrattrs"
	// Value is ignored by owner
	if err := cbor.NewEncoder(respond("csrattrs-req")).Encode(uint(0)); err != nil {
		return fmt.Errorf("error sending csrattrs-req: %w", err)
	}
	yield()
	return nil
}

func (c *CSR) createCSR(key crypto.Signer) ([]byte, error) {
	if c.CreateCSR != nil {
		return c.CreateCSR(c.Subject, key)
	}

	// Default CSR creation
	template := &x509.CertificateRequest{
		Subject: c.Subject,
	}

	return x509.CreateCertificateRequest(rand.Reader, template, key)
}

func (c *CSR) receiveCACerts(messageBody io.Reader) error {
	var certsB64 string
	if err := cbor.NewDecoder(messageBody).Decode(&certsB64); err != nil {
		return fmt.Errorf("error decoding cacerts-res: %w", err)
	}

	certsDER, err := base64.StdEncoding.DecodeString(certsB64)
	if err != nil {
		return fmt.Errorf("error decoding base64 certificates: %w", err)
	}

	// Parse certificates (could be PKCS#7 or single cert)
	certs, err := parseCertificates(certsDER)
	if err != nil {
		return fmt.Errorf("error parsing certificates: %w", err)
	}

	if c.InstallCACerts != nil {
		if err := c.InstallCACerts(certs); err != nil {
			return fmt.Errorf("error installing CA certificates: %w", err)
		}
	}

	if debugEnabled() {
		slog.Debug("fdo.csr: CA certificates received", "count", len(certs))
	}

	return nil
}

func (c *CSR) receiveEnrollment(messageBody io.Reader) error {
	var certB64 string
	if err := cbor.NewDecoder(messageBody).Decode(&certB64); err != nil {
		return fmt.Errorf("error decoding simpleenroll-res: %w", err)
	}

	certDER, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return fmt.Errorf("error decoding base64 certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("error parsing certificate: %w", err)
	}

	if c.InstallCertificate != nil {
		if err := c.InstallCertificate(cert); err != nil {
			return fmt.Errorf("error installing certificate: %w", err)
		}
	}

	if debugEnabled() {
		slog.Debug("fdo.csr: certificate enrolled", "subject", cert.Subject)
	}

	return nil
}

func (c *CSR) receiveReenrollment(messageBody io.Reader) error {
	// Same format as enrollment
	return c.receiveEnrollment(messageBody)
}

func (c *CSR) receiveServerKeygen(messageBody io.Reader) error {
	var multipartB64 string
	if err := cbor.NewDecoder(messageBody).Decode(&multipartB64); err != nil {
		return fmt.Errorf("error decoding serverkeygen-res: %w", err)
	}

	multipartData, err := base64.StdEncoding.DecodeString(multipartB64)
	if err != nil {
		return fmt.Errorf("error decoding base64 multipart: %w", err)
	}

	// Parse multipart/mixed with boundary "fdo"
	cert, key, err := parseServerKeygenResponse(multipartData)
	if err != nil {
		return fmt.Errorf("error parsing serverkeygen response: %w", err)
	}

	// Install private key first (more critical)
	if c.InstallPrivateKey != nil {
		if err := c.InstallPrivateKey(key); err != nil {
			return fmt.Errorf("error installing private key: %w", err)
		}
	}

	// Then install certificate
	if c.InstallCertificate != nil {
		if err := c.InstallCertificate(cert); err != nil {
			return fmt.Errorf("error installing certificate: %w", err)
		}
	}

	if debugEnabled() {
		slog.Debug("fdo.csr: server-generated key and certificate received", "subject", cert.Subject)
	}

	return nil
}

func (c *CSR) receiveCSRAttrs(messageBody io.Reader) error {
	var attrsB64 string
	if err := cbor.NewDecoder(messageBody).Decode(&attrsB64); err != nil {
		return fmt.Errorf("error decoding csrattrs-res: %w", err)
	}

	attrs, err := base64.StdEncoding.DecodeString(attrsB64)
	if err != nil {
		return fmt.Errorf("error decoding base64 CSR attributes: %w", err)
	}

	c.csrAttrs = attrs

	if debugEnabled() {
		slog.Debug("fdo.csr: CSR attributes received", "length", len(attrs))
	}

	return nil
}

func (c *CSR) reset() {
	c.operation = ""
	c.privateKey = nil
	c.csrAttrs = nil
	c.pendingError = nil
}

// parseCertificates parses certificates from DER-encoded data.
// Handles both single certificates and PKCS#7 bundles.
func parseCertificates(der []byte) ([]*x509.Certificate, error) {
	// Try parsing as single certificate first
	if cert, err := x509.ParseCertificate(der); err == nil {
		return []*x509.Certificate{cert}, nil
	}

	// Try parsing as PKCS#7
	// Note: Go's x509 package doesn't have built-in PKCS#7 parsing
	// For now, try PEM parsing as fallback
	block, _ := pem.Decode(der)
	if block != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return []*x509.Certificate{cert}, nil
	}

	return nil, errors.New("unable to parse certificates")
}

// parseServerKeygenResponse parses the multipart/mixed response from serverkeygen.
func parseServerKeygenResponse(data []byte) (*x509.Certificate, crypto.PrivateKey, error) {
	// The multipart data should have Content-Type header
	// For simplicity, we'll parse it manually since we know the boundary is "fdo"
	reader := multipart.NewReader(strings.NewReader(string(data)), "fdo")

	var certDER []byte
	var keyDER []byte

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("error reading multipart: %w", err)
		}

		contentType := part.Header.Get("Content-Type")
		mediaType, _, _ := mime.ParseMediaType(contentType)

		partData, err := io.ReadAll(part)
		if err != nil {
			return nil, nil, fmt.Errorf("error reading part: %w", err)
		}

		// Decode base64
		decoded, err := base64.StdEncoding.DecodeString(string(partData))
		if err != nil {
			return nil, nil, fmt.Errorf("error decoding base64 part: %w", err)
		}

		switch mediaType {
		case "application/pkcs8":
			keyDER = decoded
		case "application/pkcs7-mime":
			certDER = decoded
		}
	}

	if len(certDER) == 0 {
		return nil, nil, errors.New("no certificate found in serverkeygen response")
	}
	if len(keyDER) == 0 {
		return nil, nil, errors.New("no private key found in serverkeygen response")
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing certificate: %w", err)
	}

	// Parse PKCS#8 private key
	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing private key: %w", err)
	}

	return cert, key, nil
}

func csrErrorString(code uint) string {
	switch code {
	case 1:
		return "Bad request"
	case 2:
		return "Unauthorized"
	case 3:
		return "Feature not supported"
	case 4:
		return "Rate exceeded. Try later"
	case 5:
		return "Unsupported format"
	default:
		return "Unknown error"
	}
}
