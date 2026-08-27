// SPDX-FileCopyrightText: (C) 2024 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"time"
)

// OIDDelegateBase is the base OID for all FDO-specific extensions in delegate
// certificates (1.3.6.1.4.1.45724.3).
var OIDDelegateBase = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 3}

// OIDDelegatePermBase is the base OID for FDO delegate permissions (PERM.x).
var OIDDelegatePermBase = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 3, 1}

// OIDPermitRedirect is the fdo-ekt-permit-redirect permission OID (PERM.1).
var OIDPermitRedirect = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 3, 1, 1}

// OIDPermitOnboardNewCred is the fdo-ekt-permit-onboard-new-cred permission OID (PERM.2).
var OIDPermitOnboardNewCred = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 3, 1, 2}

// OIDPermitOnboardReuseCred is the fdo-ekt-permit-onboard-reuse-cred permission OID (PERM.3).
var OIDPermitOnboardReuseCred = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 3, 1, 3}

// OIDPermitOnboardFdoDisable is the fdo-ekt-permit-onboard-fdo-disable permission OID (PERM.4).
var OIDPermitOnboardFdoDisable = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 3, 1, 4}

// OIDPermitVoucherClaim is the fdo-ekt-permit-voucher-claim permission OID (PERM.5).
var OIDPermitVoucherClaim = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 3, 1, 5}

// OIDPermitVoucherUpload is the fdo-ekt-permit-voucher-upload permission OID (PERM.6).
var OIDPermitVoucherUpload = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 3, 1, 6}

// OIDPermitProvision is the fdo-ekt-permit-provision permission OID (PERM.7).
var OIDPermitProvision = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 3, 1, 7}

// OIDDelegateClaim is a legacy delegate OID (kept for backwards compatibility).
var OIDDelegateClaim = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 3, 4}

// OIDDelegateProvision is a legacy delegate OID for provisioning operations.
var OIDDelegateProvision = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 3, 5}

// OIDOwnershipCA is a legacy delegate OID for ownership CA operations.
var OIDOwnershipCA = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 3, 6}

// CertificateChecker is an optional callback interface for custom certificate
// validation. Implementations can use this to add revocation checking
// (CRL/OCSP) or other custom validation.
type CertificateChecker interface {
	CheckCertificate(cert *x509.Certificate) error
}

var (
	certificateChecker     CertificateChecker
	certificateCheckerOnce sync.Once
	certificateCheckerSet  bool
)

// SetCertificateChecker sets the global certificate checker for delegate chain
// validation. This should be called once at application startup.
func SetCertificateChecker(checker CertificateChecker) {
	certificateCheckerOnce.Do(func() {
		certificateChecker = checker
		certificateCheckerSet = true
	})
}

// Delegate certificate flag constants for GenerateDelegate.
const (
	DelegateFlagLeaf = iota
	DelegateFlagIntermediate
	DelegateFlagRoot
)

// DelegateOIDtoString converts a delegate OID to its human-readable string name.
func DelegateOIDtoString(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(OIDPermitRedirect):
		return "permit-redirect"
	case oid.Equal(OIDPermitOnboardNewCred):
		return "permit-onboard-new-cred"
	case oid.Equal(OIDPermitOnboardReuseCred):
		return "permit-onboard-reuse-cred"
	case oid.Equal(OIDPermitOnboardFdoDisable):
		return "permit-onboard-fdo-disable"
	case oid.Equal(OIDPermitVoucherClaim):
		return "permit-voucher-claim"
	case oid.Equal(OIDPermitVoucherUpload):
		return "permit-voucher-upload"
	case oid.Equal(OIDPermitProvision):
		return "permit-provision"
	case oid.Equal(OIDDelegateClaim):
		return "claim"
	case oid.Equal(OIDDelegateProvision):
		return "provision"
	case oid.Equal(OIDOwnershipCA):
		return "ownershipCA"
	default:
		return fmt.Sprintf("Unknown: %s", oid.String())
	}
}

// DelegateStringToOID converts a permission string name to its corresponding OID.
func DelegateStringToOID(str string) (asn1.ObjectIdentifier, error) {
	switch str {
	case "redirect", "permit-redirect":
		return OIDPermitRedirect, nil
	case "onboard-new-cred", "permit-onboard-new-cred":
		return OIDPermitOnboardNewCred, nil
	case "onboard-reuse-cred", "permit-onboard-reuse-cred":
		return OIDPermitOnboardReuseCred, nil
	case "onboard-fdo-disable", "permit-onboard-fdo-disable":
		return OIDPermitOnboardFdoDisable, nil
	case "voucher-claim", "permit-voucher-claim":
		return OIDPermitVoucherClaim, nil
	case "voucher-upload", "permit-voucher-upload":
		return OIDPermitVoucherUpload, nil
	case "provision", "permit-provision":
		return OIDPermitProvision, nil
	case "claim":
		return OIDDelegateClaim, nil
	case "legacy-provision":
		return OIDDelegateProvision, nil
	default:
		return OIDDelegateBase, fmt.Errorf("invalid delegate OID string: %s", str)
	}
}

// CertHasPermissionOID checks if a certificate has a specific permission OID.
func CertHasPermissionOID(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, o := range cert.UnknownExtKeyUsage {
		if o.Equal(oid) {
			return true
		}
	}
	return false
}

// DelegateHasPermission checks if a delegate certificate chain has a specific
// permission OID. The leaf certificate (index 0) is checked.
func DelegateHasPermission(chain []*x509.Certificate, oid asn1.ObjectIdentifier) bool {
	if len(chain) == 0 {
		return false
	}
	return CertHasPermissionOID(chain[0], oid)
}

// DelegateCanOnboard checks if a delegate certificate chain has any of the
// fdo-ekt-permit-onboard-* permissions required for TO2 onboarding.
func DelegateCanOnboard(chain []*x509.Certificate) bool {
	return DelegateHasPermission(chain, OIDPermitOnboardNewCred) ||
		DelegateHasPermission(chain, OIDPermitOnboardReuseCred) ||
		DelegateHasPermission(chain, OIDPermitOnboardFdoDisable)
}

// DelegateCanReuseCred checks if a delegate certificate chain has the
// fdo-ekt-permit-onboard-reuse-cred permission.
func DelegateCanReuseCred(chain []*x509.Certificate) bool {
	return DelegateHasPermission(chain, OIDPermitOnboardReuseCred)
}

// DelegateCanRedirect checks if a delegate certificate chain has the
// fdo-ekt-permit-redirect permission.
func DelegateCanRedirect(chain []*x509.Certificate) bool {
	return DelegateHasPermission(chain, OIDPermitRedirect)
}

// KeyUsageToString converts x509.KeyUsage flags to a human-readable string.
func KeyUsageToString(keyUsage x509.KeyUsage) string {
	var parts []string
	if keyUsage&x509.KeyUsageDigitalSignature != 0 {
		parts = append(parts, "DigitalSignature")
	}
	if keyUsage&x509.KeyUsageContentCommitment != 0 {
		parts = append(parts, "ContentCommitment")
	}
	if keyUsage&x509.KeyUsageKeyEncipherment != 0 {
		parts = append(parts, "KeyEncipherment")
	}
	if keyUsage&x509.KeyUsageDataEncipherment != 0 {
		parts = append(parts, "DataEncipherment")
	}
	if keyUsage&x509.KeyUsageKeyAgreement != 0 {
		parts = append(parts, "KeyAgreement")
	}
	if keyUsage&x509.KeyUsageCertSign != 0 {
		parts = append(parts, "CertSign")
	}
	if keyUsage&x509.KeyUsageCRLSign != 0 {
		parts = append(parts, "CRLSign")
	}
	if keyUsage&x509.KeyUsageEncipherOnly != 0 {
		parts = append(parts, "EncipherOnly")
	}
	if keyUsage&x509.KeyUsageDecipherOnly != 0 {
		parts = append(parts, "DecipherOnly")
	}
	return fmt.Sprintf("0x%x: %s", keyUsage, strings.Join(parts, " "))
}

// CertToString encodes an X.509 certificate as a PEM-formatted string.
func CertToString(cert *x509.Certificate, leader string) string {
	var pemData bytes.Buffer
	pemBlock := &pem.Block{
		Type:  leader,
		Bytes: cert.Raw,
	}
	if err := pem.Encode(&pemData, pemBlock); err != nil {
		return ""
	}
	return pemData.String()
}

// CertChainToString encodes a certificate chain as concatenated PEM blocks.
func CertChainToString(leader string, chain []*x509.Certificate) string {
	var result strings.Builder
	for _, cert := range chain {
		result.WriteString(CertToString(cert, leader))
	}
	return result.String()
}

// KeyToString returns a human-readable string representation of a public key.
func KeyToString(key crypto.PublicKey) string {
	derBytes, err := x509.MarshalPKIXPublicKey(key)
	var fingerprint string
	if err != nil {
		fingerprint = fmt.Sprintf("Err: %v", err)
	} else {
		hash := sha256.Sum256(derBytes)
		fingerprint = hex.EncodeToString(hash[:])
	}

	switch k := key.(type) {
	case *ecdsa.PublicKey:
		var curve string
		switch k.Curve {
		case elliptic.P256():
			curve = "NIST P-256 / secp256r1"
		case elliptic.P384():
			curve = "NIST P-384 / secp384r1"
		case elliptic.P521():
			curve = "NIST P-521 / secp521r1"
		default:
			curve = "Unknown"
		}
		return fmt.Sprintf("ECDSA %s Fingerprint: %s", curve, fingerprint)
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA%d Fingerprint: %s", k.Size()*8, fingerprint)
	default:
		return fmt.Sprintf("%T Fingerprint: %s", key, fingerprint)
	}
}

// DelegateChainSummary returns a brief summary of certificate common names in
// the chain.
func DelegateChainSummary(chain []*x509.Certificate) string {
	var s strings.Builder
	for _, c := range chain {
		s.WriteString(c.Subject.CommonName)
		s.WriteString("->")
	}
	return s.String()
}

func certMissingOID(c *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, o := range c.UnknownExtKeyUsage {
		if o.Equal(oid) {
			return false
		}
	}
	return true
}

//nolint:gocyclo
func processDelegateChain(chain []*x509.Certificate, ownerKey *crypto.PublicKey, oid *asn1.ObjectIdentifier, output bool) error {
	if len(chain) == 0 {
		return fmt.Errorf("delegate chain is empty")
	}

	oidArray := []asn1.ObjectIdentifier{}
	if oid != nil {
		oidArray = append(oidArray, *oid)
	}

	if ownerKey != nil {
		lastCert := chain[len(chain)-1]
		var rootPriv crypto.Signer
		var err error
		switch (*ownerKey).(type) {
		case *ecdsa.PublicKey:
			rootPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case *rsa.PublicKey:
			rootPriv, err = rsa.GenerateKey(rand.Reader, 2048)
		default:
			return fmt.Errorf("unknown key type %T", ownerKey)
		}
		if err != nil {
			return fmt.Errorf("error making ephemeral root CA key: %v", err)
		}

		template := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               lastCert.Issuer,
			RawSubject:            lastCert.RawIssuer,
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(30 * 24 * time.Hour),
			BasicConstraintsValid: true,
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
			UnknownExtKeyUsage:    oidArray,
		}

		der, err := x509.CreateCertificate(rand.Reader, template, template, *ownerKey, rootPriv)
		if err != nil {
			return fmt.Errorf("error creating ephemeral Owner Root Cert: %v", err)
		}
		rootOwner, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("error parsing ephemeral Owner Root Cert: %v", err)
		}
		chain = append(chain, rootOwner)
	}

	for i, c := range chain {
		if output {
			var permstrs []string
			for _, o := range c.UnknownExtKeyUsage {
				permstrs = append(permstrs, DelegateOIDtoString(o))
			}
			slog.Info("delegate chain cert",
				"index", i,
				"subject", c.Subject.String(),
				"issuer", c.Issuer.String(),
				"isCA", c.IsCA,
				"permissions", strings.Join(permstrs, "|"),
			)
		}

		if i != len(chain)-1 {
			if err := chain[i].CheckSignatureFrom(chain[i+1]); err != nil {
				return fmt.Errorf("delegate chain validation error - (#%d) %s not signed by (#%d) %s: %w",
					i, chain[i].Subject, i+1, chain[i+1].Subject, err)
			}
			if !bytes.Equal(chain[i].RawIssuer, chain[i+1].RawSubject) {
				return fmt.Errorf("subject %s issued by issuer=%s, expected %s",
					c.Subject, c.Issuer, chain[i+1].Subject)
			}
		}

		now := time.Now()
		if now.Before(c.NotBefore) {
			return NewCertificateValidationError(
				CertValidationErrorNotYetValid,
				c,
				"delegate chain",
				fmt.Sprintf("not yet valid (NotBefore: %v)", c.NotBefore),
			)
		}
		if now.After(c.NotAfter) {
			return NewCertificateValidationError(
				CertValidationErrorExpired,
				c,
				"delegate chain",
				fmt.Sprintf("expired (NotAfter: %v)", c.NotAfter),
			)
		}

		if certificateChecker != nil {
			if err := certificateChecker.CheckCertificate(c); err != nil {
				var certErr *CertificateValidationError
				if isRevocationError(err) {
					certErr = NewCertificateValidationError(
						CertValidationErrorRevoked,
						c,
						"delegate chain",
						err.Error(),
					)
				} else {
					certErr = NewCertificateValidationError(
						CertValidationErrorCustomCheck,
						c,
						"delegate chain",
						err.Error(),
					)
				}
				return certErr
			}
		} else if !certificateCheckerSet {
			slog.Warn("No CertificateChecker configured - revocation checking (CRL/OCSP) is disabled",
				"cert_subject", c.Subject.String(),
				"hint", "Call fdo.SetCertificateChecker() to enable custom certificate validation")
		}

		if oid != nil && certMissingOID(c, *oid) {
			return NewCertificateValidationError(
				CertValidationErrorMissingPermission,
				c,
				"delegate chain",
				fmt.Sprintf("missing required permission %v", DelegateOIDtoString(*oid)),
			)
		}

		if c.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			return NewCertificateValidationError(
				CertValidationErrorKeyUsage,
				c,
				"delegate chain",
				"No Digital Signature Usage",
			)
		}

		if !c.BasicConstraintsValid {
			return NewCertificateValidationError(
				CertValidationErrorBasicConstraints,
				c,
				"delegate chain",
				"Basic Constraints not valid",
			)
		}

		if i != 0 {
			if !c.IsCA {
				return fmt.Errorf("delegate cert %s: not a CA", c.Subject)
			}
			if c.KeyUsage&x509.KeyUsageCertSign == 0 {
				return fmt.Errorf("delegate cert %s: no CertSign usage", c.Subject)
			}
		}
	}

	return nil
}

// VerifyDelegateChain validates a delegate certificate chain against an owner key.
func VerifyDelegateChain(chain []*x509.Certificate, ownerKey *crypto.PublicKey, oid *asn1.ObjectIdentifier) error {
	return processDelegateChain(chain, ownerKey, oid, false)
}

// PrintDelegateChain validates and logs details of a delegate certificate chain.
func PrintDelegateChain(chain []*x509.Certificate, ownerKey *crypto.PublicKey, oid *asn1.ObjectIdentifier) error {
	return processDelegateChain(chain, ownerKey, oid, true)
}

// GenerateDelegate creates a delegate certificate signed by the given key.
// This is intended for testing and development use.
func GenerateDelegate(key crypto.Signer, flags uint8, delegateKey crypto.PublicKey, subject string, issuer string,
	permissions []asn1.ObjectIdentifier, sigAlg x509.SignatureAlgorithm) (*x509.Certificate, error) {
	var expandedPermissions []asn1.ObjectIdentifier
	for _, o := range permissions {
		if o.Equal(OIDDelegatePermBase) {
			expandedPermissions = append(expandedPermissions, OIDPermitOnboardNewCred)
			expandedPermissions = append(expandedPermissions, OIDPermitOnboardReuseCred)
			expandedPermissions = append(expandedPermissions, OIDPermitOnboardFdoDisable)
		} else {
			expandedPermissions = append(expandedPermissions, o)
		}
	}

	parent := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: issuer},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		UnknownExtKeyUsage:    expandedPermissions,
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: subject},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage:    expandedPermissions,
	}
	if flags&(DelegateFlagIntermediate|DelegateFlagRoot) != 0 {
		template.KeyUsage |= x509.KeyUsageCertSign
		template.IsCA = true
	}

	der, err := x509.CreateCertificate(rand.Reader, template, parent, delegateKey, key)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate returned %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	derParent, err := x509.CreateCertificate(rand.Reader, parent, parent, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("error creating parent certificate: %w", err)
	}
	certParent, err := x509.ParseCertificate(derParent)
	if err != nil {
		return nil, fmt.Errorf("error parsing parent certificate: %w", err)
	}
	if err := cert.CheckSignatureFrom(certParent); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	return cert, nil
}
