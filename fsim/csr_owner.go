// SPDX-FileCopyrightText: (C) 2024 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"mime/multipart"
	"net/textproto"
	"time"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// CSROwner implements the fdo.csr FSIM for certificate enrollment on the owner side.
// This module acts as a bridge between the device and a Certificate Authority (CA)
// or Registration Authority (RA), typically using EST (RFC 7030) protocol.
type CSROwner struct {
	// CACerts are the CA certificates to send to devices.
	// These will be sent in response to cacerts-req.
	CACerts []*x509.Certificate

	// HandleEnrollment processes a certificate enrollment request (PKCS#10 CSR).
	// It should return the signed certificate in DER format.
	// If this returns an error, an error response will be sent to the device.
	HandleEnrollment func(ctx context.Context, csrDER []byte) (*x509.Certificate, error)

	// HandleReenrollment processes a certificate re-enrollment request.
	// Similar to HandleEnrollment but for certificate renewal/rekeying.
	HandleReenrollment func(ctx context.Context, csrDER []byte, existingCert *x509.Certificate) (*x509.Certificate, error)

	// HandleServerKeygen processes a server-side key generation request.
	// It should generate a private key, create and sign a certificate, and return both.
	// The CSR is provided but its public key and signature should be ignored.
	HandleServerKeygen func(ctx context.Context, csrDER []byte) (*x509.Certificate, crypto.PrivateKey, error)

	// HandleCSRAttrs returns CSR attributes that inform the device about
	// required/optional fields in the CSR. Returns application/csrattrs format.
	HandleCSRAttrs func(ctx context.Context) ([]byte, error)

	// Internal state
	pendingResponse *pendingCSRResponse
}

type pendingCSRResponse struct {
	messageType string
	data        []byte
	errorCode   *uint
}

var _ serviceinfo.OwnerModule = (*CSROwner)(nil)

// HandleInfo implements serviceinfo.OwnerModule.
func (c *CSROwner) HandleInfo(ctx context.Context, messageName string, messageBody io.Reader) error {
	return c.ReceiveInfo(ctx, messageName, messageBody)
}

// ProduceInfo implements serviceinfo.OwnerModule.
func (c *CSROwner) ProduceInfo(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	if c.pendingResponse == nil {
		return false, false, nil
	}

	// Send pending response
	if c.pendingResponse.errorCode != nil {
		var buf bytes.Buffer
		if err := cbor.NewEncoder(&buf).Encode(*c.pendingResponse.errorCode); err != nil {
			return false, false, fmt.Errorf("error encoding error response: %w", err)
		}
		if err := producer.WriteChunk("error", buf.Bytes()); err != nil {
			return false, false, fmt.Errorf("error sending error response: %w", err)
		}
		c.pendingResponse = nil
		return false, false, nil
	}

	var buf bytes.Buffer
	if err := cbor.NewEncoder(&buf).Encode(c.pendingResponse.data); err != nil {
		return false, false, fmt.Errorf("error encoding %s: %w", c.pendingResponse.messageType, err)
	}
	if err := producer.WriteChunk(c.pendingResponse.messageType, buf.Bytes()); err != nil {
		return false, false, fmt.Errorf("error sending %s: %w", c.pendingResponse.messageType, err)
	}

	if debugEnabled() {
		slog.Debug("fdo.csr: sent response", "type", c.pendingResponse.messageType)
	}

	c.pendingResponse = nil
	return false, false, nil
}

// ReceiveInfo implements serviceinfo.OwnerModule.
func (c *CSROwner) ReceiveInfo(ctx context.Context, messageName string, messageBody io.Reader) error {
	switch messageName {
	case "cacerts-req":
		return c.handleCACertsRequest(ctx, messageBody)

	case "simpleenroll-req":
		return c.handleEnrollmentRequest(ctx, messageBody)

	case "simplereenroll-req":
		return c.handleReenrollmentRequest(ctx, messageBody)

	case "serverkeygen-req":
		return c.handleServerKeygenRequest(ctx, messageBody)

	case "csrattrs-req":
		return c.handleCSRAttrsRequest(ctx, messageBody)

	default:
		return fmt.Errorf("unknown message %s", messageName)
	}
}

func (c *CSROwner) handleCACertsRequest(ctx context.Context, messageBody io.Reader) error {
	var format uint
	if err := cbor.NewDecoder(messageBody).Decode(&format); err != nil {
		return fmt.Errorf("error decoding cacerts-req: %w", err)
	}

	if len(c.CACerts) == 0 {
		errCode := uint(1) // Bad request
		c.pendingResponse = &pendingCSRResponse{errorCode: &errCode}
		return errors.New("no CA certificates configured")
	}

	// Format 281 = application/pkcs7-mime; smime-type=certs-only
	// Format 287 = application/pkix-cert
	var certsDER []byte
	switch format {
	case 287: // Single certificate
		if len(c.CACerts) > 1 {
			errCode := uint(5) // Unsupported format
			c.pendingResponse = &pendingCSRResponse{errorCode: &errCode}
			return errors.New("multiple CA certs but single cert format requested")
		}
		certsDER = c.CACerts[0].Raw

	case 281: // PKCS#7 bundle
		// For simplicity, just send the first cert for now
		// A full implementation would create a proper PKCS#7 SignedData structure
		certsDER = c.CACerts[0].Raw

	default:
		errCode := uint(5) // Unsupported format
		c.pendingResponse = &pendingCSRResponse{errorCode: &errCode}
		return fmt.Errorf("unsupported certificate format: %d", format)
	}

	certsB64 := base64.StdEncoding.EncodeToString(certsDER)
	c.pendingResponse = &pendingCSRResponse{
		messageType: "cacerts-res",
		data:        []byte(certsB64),
	}

	if debugEnabled() {
		slog.Debug("fdo.csr: CA certificates prepared", "format", format, "count", len(c.CACerts))
	}

	return nil
}

func (c *CSROwner) handleEnrollmentRequest(ctx context.Context, messageBody io.Reader) error {
	var csrB64 string
	if err := cbor.NewDecoder(messageBody).Decode(&csrB64); err != nil {
		return fmt.Errorf("error decoding simpleenroll-req: %w", err)
	}

	csrDER, err := base64.StdEncoding.DecodeString(csrB64)
	if err != nil {
		errCode := uint(1) // Bad request
		c.pendingResponse = &pendingCSRResponse{errorCode: &errCode}
		return fmt.Errorf("error decoding base64 CSR: %w", err)
	}

	// Validate CSR
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		errCode := uint(1) // Bad request
		c.pendingResponse = &pendingCSRResponse{errorCode: &errCode}
		return fmt.Errorf("error parsing CSR: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		errCode := uint(1) // Bad request
		c.pendingResponse = &pendingCSRResponse{errorCode: &errCode}
		return fmt.Errorf("invalid CSR signature: %w", err)
	}

	// Call handler to get certificate
	if c.HandleEnrollment == nil {
		errCode := uint(3) // Feature not supported
		c.pendingResponse = &pendingCSRResponse{errorCode: &errCode}
		return errors.New("enrollment handler not configured")
	}

	cert, err := c.HandleEnrollment(ctx, csrDER)
	if err != nil {
		errCode := uint(2) // Unauthorized
		c.pendingResponse = &pendingCSRResponse{errorCode: &errCode}
		return fmt.Errorf("enrollment failed: %w", err)
	}

	certB64 := base64.StdEncoding.EncodeToString(cert.Raw)
	c.pendingResponse = &pendingCSRResponse{
		messageType: "simpleenroll-res",
		data:        []byte(certB64),
	}

	if debugEnabled() {
		slog.Debug("fdo.csr: enrollment completed", "subject", cert.Subject)
	}

	return nil
}

func (c *CSROwner) handleReenrollmentRequest(ctx context.Context, messageBody io.Reader) error {
	var csrB64 string
	if err := cbor.NewDecoder(messageBody).Decode(&csrB64); err != nil {
		return fmt.Errorf("error decoding simplereenroll-req: %w", err)
	}

	csrDER, err := base64.StdEncoding.DecodeString(csrB64)
	if err != nil {
		errCode := uint(1) // Bad request
		c.pendingResponse = &pendingCSRResponse{errorCode: &errCode}
		return fmt.Errorf("error decoding base64 CSR: %w", err)
	}

	// Validate CSR
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		errCode := uint(1) // Bad request
		c.pendingResponse = &pendingCSRResponse{errorCode: &errCode}
		return fmt.Errorf("error parsing CSR: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		errCode := uint(1) // Bad request
		c.pendingResponse = &pendingCSRResponse{errorCode: &errCode}
		return fmt.Errorf("invalid CSR signature: %w", err)
	}

	// Call handler to get certificate
	if c.HandleReenrollment == nil {
		errCode := uint(3) // Feature not supported
		c.pendingResponse = &pendingCSRResponse{errorCode: &errCode}
		return errors.New("re-enrollment handler not configured")
	}

	// Note: In a full implementation, we would extract the existing certificate
	// from the device's authentication or from a database
	cert, err := c.HandleReenrollment(ctx, csrDER, nil)
	if err != nil {
		errCode := uint(2) // Unauthorized
		c.pendingResponse = &pendingCSRResponse{errorCode: &errCode}
		return fmt.Errorf("re-enrollment failed: %w", err)
	}

	certB64 := base64.StdEncoding.EncodeToString(cert.Raw)
	c.pendingResponse = &pendingCSRResponse{
		messageType: "simplereenroll-res",
		data:        []byte(certB64),
	}

	if debugEnabled() {
		slog.Debug("fdo.csr: re-enrollment completed", "subject", cert.Subject)
	}

	return nil
}

func (c *CSROwner) handleServerKeygenRequest(ctx context.Context, messageBody io.Reader) error {
	var csrB64 string
	if err := cbor.NewDecoder(messageBody).Decode(&csrB64); err != nil {
		return fmt.Errorf("error decoding serverkeygen-req: %w", err)
	}

	csrDER, err := base64.StdEncoding.DecodeString(csrB64)
	if err != nil {
		errCode := uint(1) // Bad request
		c.pendingResponse = &pendingCSRResponse{errorCode: &errCode}
		return fmt.Errorf("error decoding base64 CSR: %w", err)
	}

	// Note: The CSR's public key and signature are ignored for server-side keygen
	// We still parse it to extract subject information

	// Call handler to generate key and certificate
	if c.HandleServerKeygen == nil {
		errCode := uint(3) // Feature not supported
		c.pendingResponse = &pendingCSRResponse{errorCode: &errCode}
		return errors.New("server-side key generation not supported")
	}

	cert, key, err := c.HandleServerKeygen(ctx, csrDER)
	if err != nil {
		errCode := uint(2) // Unauthorized
		c.pendingResponse = &pendingCSRResponse{errorCode: &errCode}
		return fmt.Errorf("server-side key generation failed: %w", err)
	}

	// Create multipart/mixed response
	multipartData, err := createServerKeygenResponse(cert, key)
	if err != nil {
		errCode := uint(1) // Bad request
		c.pendingResponse = &pendingCSRResponse{errorCode: &errCode}
		return fmt.Errorf("error creating serverkeygen response: %w", err)
	}

	multipartB64 := base64.StdEncoding.EncodeToString(multipartData)
	c.pendingResponse = &pendingCSRResponse{
		messageType: "serverkeygen-res",
		data:        []byte(multipartB64),
	}

	if debugEnabled() {
		slog.Debug("fdo.csr: server-side key generation completed", "subject", cert.Subject)
	}

	return nil
}

func (c *CSROwner) handleCSRAttrsRequest(ctx context.Context, messageBody io.Reader) error {
	var ignored uint
	if err := cbor.NewDecoder(messageBody).Decode(&ignored); err != nil {
		return fmt.Errorf("error decoding csrattrs-req: %w", err)
	}

	if c.HandleCSRAttrs == nil {
		errCode := uint(3) // Feature not supported
		c.pendingResponse = &pendingCSRResponse{errorCode: &errCode}
		return errors.New("CSR attributes not supported")
	}

	attrs, err := c.HandleCSRAttrs(ctx)
	if err != nil {
		errCode := uint(1) // Bad request
		c.pendingResponse = &pendingCSRResponse{errorCode: &errCode}
		return fmt.Errorf("error getting CSR attributes: %w", err)
	}

	attrsB64 := base64.StdEncoding.EncodeToString(attrs)
	c.pendingResponse = &pendingCSRResponse{
		messageType: "csrattrs-res",
		data:        []byte(attrsB64),
	}

	if debugEnabled() {
		slog.Debug("fdo.csr: CSR attributes prepared", "length", len(attrs))
	}

	return nil
}

// createServerKeygenResponse creates a multipart/mixed response with certificate and private key.
func createServerKeygenResponse(cert *x509.Certificate, key crypto.PrivateKey) ([]byte, error) {
	// Marshal private key to PKCS#8
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("error marshaling private key: %w", err)
	}

	// Create multipart writer with boundary "fdo"
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	if err := writer.SetBoundary("fdo"); err != nil {
		return nil, fmt.Errorf("error setting boundary: %w", err)
	}

	// Write private key part
	keyHeader := textproto.MIMEHeader{}
	keyHeader.Set("Content-Type", "application/pkcs8")
	keyHeader.Set("Content-Transfer-Encoding", "base64")
	keyPart, err := writer.CreatePart(keyHeader)
	if err != nil {
		return nil, fmt.Errorf("error creating key part: %w", err)
	}
	if _, err := keyPart.Write([]byte(base64.StdEncoding.EncodeToString(keyDER))); err != nil {
		return nil, fmt.Errorf("error writing key part: %w", err)
	}

	// Write certificate part
	certHeader := textproto.MIMEHeader{}
	certHeader.Set("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
	certHeader.Set("Content-Transfer-Encoding", "base64")
	certPart, err := writer.CreatePart(certHeader)
	if err != nil {
		return nil, fmt.Errorf("error creating cert part: %w", err)
	}
	if _, err := certPart.Write([]byte(base64.StdEncoding.EncodeToString(cert.Raw))); err != nil {
		return nil, fmt.Errorf("error writing cert part: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("error closing multipart writer: %w", err)
	}

	return buf.Bytes(), nil
}

// Helper functions for certificate generation

func mustRandomSerial() *big.Int {
	maxVal := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, maxVal)
	if err != nil {
		panic(fmt.Sprintf("failed to generate serial number: %v", err))
	}
	return serial
}

func mustTimeNow() time.Time {
	return time.Now()
}

// SelfSignedEnrollmentHandler is a simple enrollment handler that creates self-signed certificates.
// This is useful for testing but should NOT be used in production.
func SelfSignedEnrollmentHandler(signerKey crypto.Signer) func(context.Context, []byte) (*x509.Certificate, error) {
	return func(ctx context.Context, csrDER []byte) (*x509.Certificate, error) {
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			return nil, err
		}

		// Create a simple certificate template
		template := &x509.Certificate{
			SerialNumber: mustRandomSerial(),
			Subject:      csr.Subject,
			NotBefore:    mustTimeNow(),
			NotAfter:     mustTimeNow().AddDate(1, 0, 0), // 1 year
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}

		certDER, err := x509.CreateCertificate(rand.Reader, template, template, csr.PublicKey, signerKey)
		if err != nil {
			return nil, err
		}

		return x509.ParseCertificate(certDER)
	}
}
