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
	"math/big"
	"os"
	"strings"
	"time"
)

// These OIDs are constants defined under "Delegate Protocol" in the specification
// Per spec section on x509keytypes: PERM.x means OID 1.3.6.1.4.1.45724.3.1.x

var OID_delegateBase asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 3}

// Permission OIDs under 1.3.6.1.4.1.45724.3.1.x (PERM.x)
var OID_delegatePermBase asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 3, 1}
var OID_permitRedirect asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 3, 1, 1}          // fdo-ekt-permit-redirect (PERM.1)
var OID_permitOnboardNewCred asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 3, 1, 2}    // fdo-ekt-permit-onboard-new-cred (PERM.2)
var OID_permitOnboardReuseCred asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 3, 1, 3}  // fdo-ekt-permit-onboard-reuse-cred (PERM.3)
var OID_permitOnboardFdoDisable asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 3, 1, 4} // fdo-ekt-permit-onboard-fdo-disable (PERM.4)

// Legacy OIDs (kept for backwards compatibility)
var OID_delegateClaim asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 3, 4}
var OID_delegateProvision asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 3, 5}
var OID_ownershipCA asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 3, 6}

func DelegateOIDtoString(oid asn1.ObjectIdentifier) string {
	// New permission OIDs (PERM.x)
	if oid.Equal(OID_permitRedirect) {
		return "permit-redirect"
	}
	if oid.Equal(OID_permitOnboardNewCred) {
		return "permit-onboard-new-cred"
	}
	if oid.Equal(OID_permitOnboardReuseCred) {
		return "permit-onboard-reuse-cred"
	}
	if oid.Equal(OID_permitOnboardFdoDisable) {
		return "permit-onboard-fdo-disable"
	}
	// Legacy OIDs
	if oid.Equal(OID_delegateClaim) {
		return "claim"
	}
	if oid.Equal(OID_delegateProvision) {
		return "provision"
	}
	if oid.Equal(OID_ownershipCA) {
		return "ownershipCA"
	}
	return fmt.Sprintf("Unknown: %s\n", oid.String())
}

func DelegateStringToOID(str string) (asn1.ObjectIdentifier, error) {
	switch str {
	// New permission OIDs
	case "redirect", "permit-redirect":
		return OID_permitRedirect, nil
	case "onboard-new-cred", "permit-onboard-new-cred":
		return OID_permitOnboardNewCred, nil
	case "onboard-reuse-cred", "permit-onboard-reuse-cred":
		return OID_permitOnboardReuseCred, nil
	case "onboard-fdo-disable", "permit-onboard-fdo-disable":
		return OID_permitOnboardFdoDisable, nil
	// Legacy OIDs
	case "claim":
		return OID_delegateClaim, nil
	case "provision":
		return OID_delegateProvision, nil
	default:
		return OID_delegateBase, fmt.Errorf("invalid delegate OID string: %s", str)
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
	return DelegateHasPermission(chain, OID_permitOnboardNewCred) ||
		DelegateHasPermission(chain, OID_permitOnboardReuseCred) ||
		DelegateHasPermission(chain, OID_permitOnboardFdoDisable)
}

// DelegateCanReuseCred checks if a delegate certificate chain has the
// fdo-ekt-permit-onboard-reuse-cred permission required for credential reuse.
// Per spec: Delegates MUST have fdo-ekt-permit-onboard-reuse-cred to instruct
// endpoint to use reuse protocol.
func DelegateCanReuseCred(chain []*x509.Certificate) bool {
	return DelegateHasPermission(chain, OID_permitOnboardReuseCred)
}

// DelegateCanRedirect checks if a delegate certificate chain has the
// fdo-ekt-permit-redirect permission required for TO0/TO1.
func DelegateCanRedirect(chain []*x509.Certificate) bool {
	return DelegateHasPermission(chain, OID_permitRedirect)
}

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

// Helper functions for certificates and keys

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

// Take raw PEM encoded byte array and convert to a
// human-readable certificate string
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
func CertChainToString(leader string, chain []*x509.Certificate) string {
	var result = ""
	for _, cert := range chain {
		result += CertToString(cert, leader)
	}

	return result
}

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
// optionall for a given function
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
			return fmt.Errorf("Unknown key type %T", ownerKey)
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

		// Cheeck Signatures on each
		if i != len(chain)-1 {
			err := chain[i].CheckSignatureFrom(chain[i+1])
			if err != nil {
				if output {
					fmt.Print("THIS CERT:\n")
					fmt.Print(CertToString(chain[i], "CERTIFICATE"))
					fmt.Print("...WAS NOT SIGNED BY....\n")
					fmt.Print(CertToString(chain[i+1], "CERTIFICATE"))
				}
				return fmt.Errorf("VerifyDelegate Chain Validation error - (#%d) %s not signed by (#%d) %s: %v\n", i, chain[i].Subject, i+1, chain[i+1].Subject, err)
			}
			if chain[i].Issuer.CommonName != chain[i+1].Subject.CommonName {
				return fmt.Errorf("Subject %s Issued by Issuer=%s, expected %s", c.Subject, c.Issuer, chain[i+1].Issuer)
			}
		}

		// TODO we do NOT check expiration or revocation

		if (oid != nil) && (certMissingOID(c, *oid)) {
			return fmt.Errorf("VerifyDelegate error - %s has no permission %v\n", c.Subject, DelegateOIDtoString(*oid))
		}
		if (c.KeyUsage & x509.KeyUsageDigitalSignature) == 0 {
			return fmt.Errorf("VerifyDelegate cert %s: No Digital Signature Usage", c.Subject)
		}
		if c.BasicConstraintsValid == false {
			return fmt.Errorf("VerifyDelegate cert %s: Basic Constraints not valid", c.Subject)
		}

		// Leaf cert does not need to be a CA, but others do
		if i != 0 {
			if c.IsCA == false {
				return fmt.Errorf("VerifyDelegate cert %s: Not a CA", c.Subject)
			}
			if (c.KeyUsage & x509.KeyUsageCertSign) == 0 {
				return fmt.Errorf("VerifyDelegate cert %s: No CerSign Usage", c.Subject)
			}
		}
	}

	return nil
}

func VerifyDelegateChain(chain []*x509.Certificate, ownerKey *crypto.PublicKey, oid *asn1.ObjectIdentifier) error {
	return processDelegateChain(chain, ownerKey, oid, false)
}

func PrintDelegateChain(chain []*x509.Certificate, ownerKey *crypto.PublicKey, oid *asn1.ObjectIdentifier) error {
	return processDelegateChain(chain, ownerKey, oid, true)
}

func DelegateChainSummary(chain []*x509.Certificate) (s string) {
	for _, c := range chain {
		s += c.Subject.CommonName + "->"
	}
	return
}

// This is a helper function, but also used in the verification process
// Certificates generated are temporary and should not be used for production
// Per spec, permissions should include the discrete OID_permit* OIDs:
//   - OID_permitRedirect for TO0/TO1 redirect
//   - OID_permitOnboardNewCred for onboarding with new credentials
//   - OID_permitOnboardReuseCred for credential reuse
//   - OID_permitOnboardFdoDisable for FDO disable after onboard
func GenerateDelegate(key crypto.Signer, flags uint8, delegateKey crypto.PublicKey, subject string, issuer string,
	permissions []asn1.ObjectIdentifier, sigAlg x509.SignatureAlgorithm) (*x509.Certificate, error) {
	// Permissions should use discrete OIDs (OID_permit*) directly in UnknownExtKeyUsage.
	// For backwards compatibility, if OID_delegatePermBase is passed, we expand it to all onboard permissions.
	var expandedPermissions []asn1.ObjectIdentifier
	for _, o := range permissions {
		if o.Equal(OID_delegatePermBase) {
			// Expand legacy base OID to all three onboard permission OIDs
			expandedPermissions = append(expandedPermissions, OID_permitOnboardNewCred)
			expandedPermissions = append(expandedPermissions, OID_permitOnboardReuseCred)
			expandedPermissions = append(expandedPermissions, OID_permitOnboardFdoDisable)
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
	certParent, err := x509.ParseCertificate(derParent)
	err = cert.CheckSignatureFrom(certParent)
	if err != nil {
		fmt.Printf("Verify error is: %v\n", err)
	}

	return cert, nil
}

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
