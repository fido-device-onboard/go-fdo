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
	"os"
	"reflect"
	"strings"
	"sync"
	"time"
)

// OIDDelegateBase is the base OID for all FDO-specific extensions in delegate certificates (1.3.6.1.4.1.45724.3).
// This covers all delegate-related fields specified in the FDO Delegate Protocol.
var OIDDelegateBase = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 3}

// OIDDelegatePermBase is the base OID for FDO delegate permissions (PERM.x).
// Permissions are binary: if an issuer has a permission OID, all certificates it issues
// must also include that OID to inherit the permission.
var OIDDelegatePermBase = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 3, 1}

// OIDPermitRedirect is the fdo-ekt-permit-redirect permission OID (PERM.1).
var OIDPermitRedirect = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 3, 1, 1}

// OIDPermitOnboardNewCred is the fdo-ekt-permit-onboard-new-cred permission OID (PERM.2).
var OIDPermitOnboardNewCred = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 3, 1, 2}

// OIDPermitOnboardReuseCred is the fdo-ekt-permit-onboard-reuse-cred permission OID (PERM.3).
var OIDPermitOnboardReuseCred = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 3, 1, 3}

// OIDPermitOnboardFdoDisable is the fdo-ekt-permit-onboard-fdo-disable permission OID (PERM.4).
var OIDPermitOnboardFdoDisable = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 3, 1, 4}

// OIDDelegateClaim is a legacy delegate OID (kept for backwards compatibility).
var OIDDelegateClaim = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 3, 4}

// OIDDelegateProvision is a legacy delegate OID for provisioning operations.
var OIDDelegateProvision = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 3, 5}

// OIDOwnershipCA is a legacy delegate OID for ownership CA operations.
var OIDOwnershipCA = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 3, 6}

// CertificateChecker is an optional callback interface for custom certificate validation.
// Implementations can use this to add revocation checking (CRL/OCSP) or other custom validation.
// If CheckCertificate returns an error, the delegate chain validation will fail.
type CertificateChecker interface {
	// CheckCertificate performs custom validation on a certificate.
	// It is called for each certificate in the delegate chain during validation.
	// Return nil if the certificate is valid, or an error to reject it.
	CheckCertificate(cert *x509.Certificate) error
}

var (
	certificateChecker     CertificateChecker
	certificateCheckerOnce sync.Once
	certificateCheckerSet  bool
)

// SetCertificateChecker sets the global certificate checker for delegate chain validation.
// This should be called once at application startup to enable custom certificate validation
// such as revocation checking (CRL/OCSP).
//
// Example usage for OCSP checking:
//
//	type OCSPChecker struct{}
//	func (c *OCSPChecker) CheckCertificate(cert *x509.Certificate) error {
//	    // Implement OCSP checking here
//	    return nil
//	}
//	fdo.SetCertificateChecker(&OCSPChecker{})
func SetCertificateChecker(checker CertificateChecker) {
	certificateCheckerOnce.Do(func() {
		certificateChecker = checker
		certificateCheckerSet = true
	})
}

// DelegateOIDtoString converts a delegate OID to its human-readable string name.
func DelegateOIDtoString(oid asn1.ObjectIdentifier) string {
	// New permission OIDs (PERM.x)
	if oid.Equal(OIDPermitRedirect) {
		return "permit-redirect"
	}
	if oid.Equal(OIDPermitOnboardNewCred) {
		return "permit-onboard-new-cred"
	}
	if oid.Equal(OIDPermitOnboardReuseCred) {
		return "permit-onboard-reuse-cred"
	}
	if oid.Equal(OIDPermitOnboardFdoDisable) {
		return "permit-onboard-fdo-disable"
	}
	// Legacy OIDs
	if oid.Equal(OIDDelegateClaim) {
		return "claim"
	}
	if oid.Equal(OIDDelegateProvision) {
		return "provision"
	}
	if oid.Equal(OIDOwnershipCA) {
		return "ownershipCA"
	}
	return fmt.Sprintf("Unknown: %s\n", oid.String())
}

// DelegateStringToOID converts a permission string name to its corresponding OID.
func DelegateStringToOID(str string) (asn1.ObjectIdentifier, error) {
	switch str {
	// New permission OIDs
	case "redirect", "permit-redirect":
		return OIDPermitRedirect, nil
	case "onboard-new-cred", "permit-onboard-new-cred":
		return OIDPermitOnboardNewCred, nil
	case "onboard-reuse-cred", "permit-onboard-reuse-cred":
		return OIDPermitOnboardReuseCred, nil
	case "onboard-fdo-disable", "permit-onboard-fdo-disable":
		return OIDPermitOnboardFdoDisable, nil
	// Legacy OIDs
	case "claim":
		return OIDDelegateClaim, nil
	case "provision":
		return OIDDelegateProvision, nil
	default:
		return OIDDelegateBase, fmt.Errorf("invalid delegate OID string: %s", str)
	}
}
func certMissingOID(c *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, o := range c.UnknownExtKeyUsage {
		if o.Equal(oid) {
			return false
		}
	}
	return true
}

// CertHasPermissionOID checks if a certificate has a specific permission OID
// in its ExtKeyUsage or UnknownExtKeyUsage fields.
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
// Use the OID_permit* constants for the oid parameter.
func DelegateHasPermission(chain []*x509.Certificate, oid asn1.ObjectIdentifier) bool {
	if len(chain) == 0 {
		return false
	}
	return CertHasPermissionOID(chain[0], oid)
}

// DelegateCanOnboard checks if a delegate certificate chain has any of the
// fdo-ekt-permit-onboard-* permissions required for TO2 onboarding.
// Per spec: Any of the three fdo-ekt-permit-onboard- permissions are REQUIRED
// for a Delegate to be able to onboard a device via TO2.
func DelegateCanOnboard(chain []*x509.Certificate) bool {
	return DelegateHasPermission(chain, OIDPermitOnboardNewCred) ||
		DelegateHasPermission(chain, OIDPermitOnboardReuseCred) ||
		DelegateHasPermission(chain, OIDPermitOnboardFdoDisable)
}

// DelegateCanReuseCred checks if a delegate certificate chain has the
// fdo-ekt-permit-onboard-reuse-cred permission required for credential reuse.
// Per spec: Delegates MUST have fdo-ekt-permit-onboard-reuse-cred to instruct
// endpoint to use reuse protocol.
func DelegateCanReuseCred(chain []*x509.Certificate) bool {
	return DelegateHasPermission(chain, OIDPermitOnboardReuseCred)
}

// DelegateCanRedirect checks if a delegate certificate chain has the
// fdo-ekt-permit-redirect permission required for TO0/TO1.
func DelegateCanRedirect(chain []*x509.Certificate) bool {
	return DelegateHasPermission(chain, OIDPermitRedirect)
}

// KeyUsageToString converts x509.KeyUsage flags to a human-readable string.
func KeyUsageToString(keyUsage x509.KeyUsage) (s string) {
	s = fmt.Sprintf("0x%x: ", keyUsage)
	if (int(keyUsage) & int(x509.KeyUsageDigitalSignature)) != 0 {
		s += "KeyUsageDigitalSignature "
	}
	if (int(keyUsage) & int(x509.KeyUsageContentCommitment)) != 0 {
		s += "KeyUsageContentCommitment "
	}
	if (int(keyUsage) & int(x509.KeyUsageKeyEncipherment)) != 0 {
		s += "KeyUsageKeyEncipherment "
	}
	if (int(keyUsage) & int(x509.KeyUsageDataEncipherment)) != 0 {
		s += "KeyUsageDataEncipherment "
	}
	if (int(keyUsage) & int(x509.KeyUsageKeyAgreement)) != 0 {
		s += "KeyUsageKeyAgreement "
	}
	if (int(keyUsage) & int(x509.KeyUsageCertSign)) != 0 {
		s += "KeyUsageCertSign "
	}
	if (int(keyUsage) & int(x509.KeyUsageCRLSign)) != 0 {
		s += "KeyUsageCRLSign "
	}
	if (int(keyUsage) & int(x509.KeyUsageEncipherOnly)) != 0 {
		s += "KeyUsageEncipherOnly "
	}
	if (int(keyUsage) & int(x509.KeyUsageDecipherOnly)) != 0 {
		s += "KeyUsageDecipherOnly "
	}
	return
}

// "Leaf" certs cannot sign other certs
const (
	DelegateFlagLeaf = iota
	DelegateFlagIntermediate
	DelegateFlagRoot
)

// CertToString encodes an X.509 certificate as a PEM-formatted string.
func CertToString(cert *x509.Certificate, leader string) string {
	var pemData bytes.Buffer
	pemBlock := &pem.Block{
		Type:  leader,
		Bytes: cert.Raw,
	}
	if err := pem.Encode(&pemData, pemBlock); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to encode certificate: %v\n", err)
		return ""
	}

	return (pemData.String())
}

// BytesToString encodes raw certificate bytes as a PEM-formatted string.
func BytesToString(b []byte, leader string) string {
	// This is just going to take raw certificate bytes and dump to base64
	// inside BEGIN/END Certificate block
	var pemData bytes.Buffer
	pemBlock := &pem.Block{
		Type:  leader, // Should be usually "CERTIFICATE"
		Bytes: b,
	}
	if err := pem.Encode(&pemData, pemBlock); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to encode certificate: %v\n", err)
		return ""
	}
	return pemData.String()
}

// CertChainToString encodes a certificate chain as concatenated PEM blocks.
func CertChainToString(leader string, chain []*x509.Certificate) string {
	var result = ""
	for _, cert := range chain {
		result += CertToString(cert, leader)
	}

	return result
}

// PrivKeyToString encodes a private key as a PEM-formatted string.
func PrivKeyToString(key any) string {
	var pemData bytes.Buffer
	var pemBlock *pem.Block
	switch k := key.(type) {
	case *rsa.PrivateKey:
		der := x509.MarshalPKCS1PrivateKey(k)
		pemBlock = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		}
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return ""
		}
		pemBlock = &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: der,
		}

	default:
		return ""
	}

	err := pem.Encode(&pemData, pemBlock)
	if err != nil {
		return ""
	}
	return pemData.String()
}

// Verify a delegate chain against an optional owner key,
// optionally for a given function
//
//nolint:gocyclo // Protocol validation requires multiple checks
func processDelegateChain(chain []*x509.Certificate, ownerKey *crypto.PublicKey, oid *asn1.ObjectIdentifier, output bool) error {

	oidArray := []asn1.ObjectIdentifier{}
	if oid != nil {
		oidArray = append(oidArray, *oid)
	}
	// If requested, verify that chain was rooted by Owner Key since we will often not have a cert for the Owner Key,
	// we will have to add a self-signed owner cert at the root of the chain
	if ownerKey != nil {
		issuer := chain[len(chain)-1].Issuer.CommonName
		public := ownerKey
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
			return fmt.Errorf("VerifyDelegate Error making ephemeral root CA key: %v", err)
		}
		if output {
			fmt.Printf("Ephemeral Root Key: %s\n", KeyToString(rootPriv.Public()))
		}
		rootOwner, err := GenerateDelegate(rootPriv, DelegateFlagRoot, *public, issuer, issuer, oidArray, 0)
		if err != nil {
			return fmt.Errorf("VerifyDelegate Error createing ephemerial Owner Root Cert: %v", err)
		}
		chain = append(chain, rootOwner)
	}

	permstr := ""
	for i, c := range chain {
		var permstrs []string
		for _, o := range c.UnknownExtKeyUsage {
			s := DelegateOIDtoString(o)
			permstrs = append(permstrs, s)
		}
		permstr = strings.Join(permstrs, "|")

		if output {
			fmt.Printf("%d: Subject=%s Issuer=%s  Algo=%s IsCA=%v KeyUsage=%s Perms=[%s] KeyType=%s\n", i, c.Subject, c.Issuer,
				c.SignatureAlgorithm.String(), c.IsCA, KeyUsageToString(c.KeyUsage), permstr, KeyToString(c.PublicKey))
		}

		// Check Signatures on each
		if i != len(chain)-1 {
			err := chain[i].CheckSignatureFrom(chain[i+1])
			if err != nil {
				if output {
					fmt.Print("THIS CERT:\n")
					fmt.Print(CertToString(chain[i], "CERTIFICATE"))
					fmt.Print("...WAS NOT SIGNED BY....\n")
					fmt.Print(CertToString(chain[i+1], "CERTIFICATE"))
				}
				return fmt.Errorf("verifyDelegate chain validation error - (#%d) %s not signed by (#%d) %s: %w", i, chain[i].Subject, i+1, chain[i+1].Subject, err)
			}
			if !bytes.Equal(chain[i].RawIssuer, chain[i+1].RawSubject) {
				return fmt.Errorf("subject %s issued by issuer=%s, expected %s", c.Subject, c.Issuer, chain[i+1].Subject)
			}
		}

		// Check certificate expiration
		now := time.Now()
		if now.Before(c.NotBefore) {
			err := NewCertificateValidationError(
				CertValidationErrorNotYetValid,
				c,
				"delegate chain",
				fmt.Sprintf("not yet valid (NotBefore: %v)", c.NotBefore),
			)
			return err
		}
		if now.After(c.NotAfter) {
			err := NewCertificateValidationError(
				CertValidationErrorExpired,
				c,
				"delegate chain",
				fmt.Sprintf("expired (NotAfter: %v)", c.NotAfter),
			)
			return err
		}

		// Call custom certificate checker if configured (e.g., for revocation checking)
		if certificateChecker != nil {
			var certErr *CertificateValidationError

			// Try to use enhanced checker by checking for the specific method signature
			// We use interface{} to avoid the conflicting method signature issue
			if checkerVal := reflect.ValueOf(certificateChecker); checkerVal.IsValid() {
				method := checkerVal.MethodByName("CheckCertificate")
				if method.IsValid() {
					methodType := method.Type()
					// Check if the method returns *CertificateValidationError
					if methodType.NumOut() == 1 && methodType.Out(0) == reflect.TypeOf((*CertificateValidationError)(nil)).Elem() {
						// This is an enhanced checker
						result := method.Call([]reflect.Value{reflect.ValueOf(c)})
						if len(result) == 1 && !result[0].IsNil() {
							certErr = result[0].Interface().(*CertificateValidationError)
						}
					} else {
						// This is a legacy checker
						result := method.Call([]reflect.Value{reflect.ValueOf(c)})
						if len(result) == 1 && !result[0].IsNil() {
							if err, ok := result[0].Interface().(error); ok {
								// Wrap legacy error
								if isRevocationError(err) {
									certErr = NewCertificateValidationError(
										CertValidationErrorRevoked,
										c,
										"custom certificate check",
										err.Error(),
									)
								} else {
									certErr = NewCertificateValidationError(
										CertValidationErrorCustomCheck,
										c,
										"custom certificate check",
										err.Error(),
									)
								}
							}
						}
					}
				}
			}

			if certErr != nil {
				certErr.Context = "delegate chain"
				return certErr
			}
		} else if !certificateCheckerSet {
			// Warn that no certificate checker is configured - revocation is not being checked
			slog.Warn("No CertificateChecker configured - revocation checking (CRL/OCSP) is disabled",
				"cert_subject", c.Subject.String(),
				"hint", "Call fdo.SetCertificateChecker() to enable custom certificate validation")
		}

		if (oid != nil) && (certMissingOID(c, *oid)) {
			return NewCertificateValidationError(
				CertValidationErrorMissingPermission,
				c,
				"delegate chain",
				fmt.Sprintf("missing required permission %v", DelegateOIDtoString(*oid)),
			)
		}
		if (c.KeyUsage & x509.KeyUsageDigitalSignature) == 0 {
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

		// Leaf cert does not need to be a CA, but others do
		if i != 0 {
			if !c.IsCA {
				return fmt.Errorf("VerifyDelegate cert %s: Not a CA", c.Subject)
			}
			if (c.KeyUsage & x509.KeyUsageCertSign) == 0 {
				return fmt.Errorf("VerifyDelegate cert %s: No CerSign Usage", c.Subject)
			}
		}
	}

	return nil
}

// VerifyDelegateChain validates a delegate certificate chain against an owner key.
func VerifyDelegateChain(chain []*x509.Certificate, ownerKey *crypto.PublicKey, oid *asn1.ObjectIdentifier) error {
	return processDelegateChain(chain, ownerKey, oid, false)
}

// PrintDelegateChain validates and prints details of a delegate certificate chain.
func PrintDelegateChain(chain []*x509.Certificate, ownerKey *crypto.PublicKey, oid *asn1.ObjectIdentifier) error {
	return processDelegateChain(chain, ownerKey, oid, true)
}

// DelegateChainSummary returns a brief summary of certificate common names in the chain.
func DelegateChainSummary(chain []*x509.Certificate) (s string) {
	for _, c := range chain {
		s += c.Subject.CommonName + "->"
	}
	return
}

// GenerateDelegate creates a delegate certificate signed by the given key.
// Certificates generated are temporary and should not be used for production.
func GenerateDelegate(key crypto.Signer, flags uint8, delegateKey crypto.PublicKey, subject string, issuer string,
	permissions []asn1.ObjectIdentifier, sigAlg x509.SignatureAlgorithm) (*x509.Certificate, error) {
	// Permissions should use discrete OIDs (OID_permit*) directly in UnknownExtKeyUsage.
	// For backwards compatibility, if OIDDelegatePermBase is passed, we expand it to all onboard permissions.
	var expandedPermissions []asn1.ObjectIdentifier
	for _, o := range permissions {
		if o.Equal(OIDDelegatePermBase) {
			// Expand legacy base OID to all three onboard permission OIDs
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
	if (flags & (DelegateFlagIntermediate | DelegateFlagRoot)) != 0 {
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

	// Let's Verify...
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
		curve := ""
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
