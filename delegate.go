// SPDX-FileCopyrightText: (C) 2024 Intel Corporation and Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"fmt"
	"encoding/pem"
	"os"
	"bytes"
	"crypto/x509"
	"crypto/rsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"time"
	"crypto"
	"encoding/asn1"
	"crypto/x509/pkix"
)

func certMissingOID(c *x509.Certificate,oid asn1.ObjectIdentifier) bool {
	for _,o := range c.UnknownExtKeyUsage {
		if (o.Equal(oid)) {
			return false
		}
	}
	return true
}

func KeyUsageToString(keyUsage x509.KeyUsage) (s string) {
	s = fmt.Sprintf("0x%x: ",keyUsage)
	if (int(keyUsage) & int(x509.KeyUsageDigitalSignature)) != 0 { s+= "KeyUsageDigitalSignature " }
	if (int(keyUsage) & int(x509.KeyUsageContentCommitment)) != 0 { s+= "KeyUsageContentCommitment " }
	if (int(keyUsage) & int(x509.KeyUsageKeyEncipherment)) != 0 { s+= "KeyUsageKeyEncipherment " }
	if (int(keyUsage) & int(x509.KeyUsageDataEncipherment)) != 0 { s+= "KeyUsageDataEncipherment " }
	if (int(keyUsage) & int(x509.KeyUsageKeyAgreement)) != 0 { s+= "KeyUsageKeyAgreement " }
	if (int(keyUsage) & int(x509.KeyUsageCertSign)) != 0 { s+= "KeyUsageCertSign " }
	if (int(keyUsage) & int(x509.KeyUsageCRLSign)) != 0 { s+= "KeyUsageCRLSign " }
	if (int(keyUsage) & int(x509.KeyUsageEncipherOnly)) != 0 { s+= "KeyUsageEncipherOnly " }
	if (int(keyUsage) & int(x509.KeyUsageDecipherOnly)) != 0 { s+= "KeyUsageDecipherOnly " }
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

	return(pemData.String())
}
// Take raw PEM enclodes byte array and convert to a 
// human-readible certificate string
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
func CertChainToString(leader string,chain []*x509.Certificate) string {
	var result=""
	for _, cert := range chain {
		result += CertToString(cert,leader)
	}

	return result
}

func PrivKeyToString(key any) string {
	var pemData bytes.Buffer
	var pemBlock *pem.Block
	switch key.(type) {
		case *rsa.PrivateKey:
			der := x509.MarshalPKCS1PrivateKey(key.(*rsa.PrivateKey))
			pemBlock = &pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: der,
			}
		case *ecdsa.PrivateKey:
			der, err := x509.MarshalECPrivateKey(key.(*ecdsa.PrivateKey))
			if err != nil {
				return ""
			}
			pemBlock = &pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: der,
			}

		default:
			return ("")
	}

	err := pem.Encode(&pemData, pemBlock)
	if (err != nil) {
		return ""
	}
	return pemData.String()
}


//TODO DEPRICATE
func VerifyCertChain(pubKey any, chain []*x509.Certificate) error {
	cert := chain[0]
	var parentPriv any
	var parentPub any
	var err error

	// Generate a new private key for the parent
	switch pubKey := pubKey.(type) {
	case *ecdsa.PublicKey:
		parentPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("Error creating ephemeral ECDSA key: %w", err)
		}
		parentPub = pubKey
	case *rsa.PublicKey:
		parentPriv, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("Error creating ephemeral RSA key: %w", err)
		}
		parentPub = pubKey
	default:
		return fmt.Errorf("Invalid key type %T", pubKey)
	}

	// Create a template for the parent certificate
	parentTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		//Subject: pkix.Name{ Organization: []string{"Parent Organization"}, },
		NotBefore:			 time.Now(),
		NotAfter:			  time.Now().Add(time.Minute), 
		KeyUsage:			  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:		   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:				  true,
	}

	// Create the parent certificate with the provided public key
	parentCertDER, err := x509.CreateCertificate(rand.Reader, &parentTemplate, &parentTemplate, parentPub, parentPriv)
	if err != nil {
		return fmt.Errorf("Failed to create parent certificate: %w", err)
	}

	// Parse the parent certificate
	parentCert, err := x509.ParseCertificate(parentCertDER)
	if err != nil {
		return fmt.Errorf("Failed to parse parent certificate: %w", err)
	}

	// Verify the given certificate using the parent certificate's public key
	err = cert.CheckSignatureFrom(parentCert)
	if err != nil {
		return fmt.Errorf("Failed to verify certificate signature: %w", err)
	}

	fmt.Println("Certificate signature verified successfully")
	return nil
}

// Verify a delegate chain against an optional owner key, 
// optionall for a given function
func VerifyDelegateChain(chain []*x509.Certificate, ownerKey *crypto.PublicKey, oid *asn1.ObjectIdentifier) error {

	// If requested, verify that chain was rooted by Owner Key since we will often not have a cert for the Owner Key,
	// we will have to make one (with Owner's Public Key) - and put it as the root of the chain
	if (ownerKey != nil) {
		issuer := chain[0].Issuer.CommonName
		public := ownerKey
		rootPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if (err != nil) { return fmt.Errorf("VerifyDelegate Error making ephemeral root CA key: %v",err) }
		rootOwner, err := GenerateDelegate(rootPriv, DelegateFlagRoot , *public,issuer,issuer)
		if (err != nil) {
			return fmt.Errorf("VerifyDelegate Error createing ephemerial Owner Root Cert: %v",err)
		}
		chain = append([]*x509.Certificate{rootOwner},chain...)
	}

	for i,c := range chain {
		if (i!= 0) {
			fmt.Printf("%d: Subject=%s Issuer=%s IsCA=%v KeyUsage=%s CheckFrom %s\n",i,c.Subject,c.Issuer,c.IsCA,KeyUsageToString(c.KeyUsage),chain[i-1].Subject)
			//fmt.Printf("%d: ExtKey=%+v\n",i,c.UnknownExtKeyUsage)
			err := chain[i].CheckSignatureFrom(chain[i-1])
			if (err != nil) {
				return fmt.Errorf("VerifyDelegate Chain Validation error - %d not signed by %d: %v\n",i,i-1,err)
			}
			if (chain[i].Issuer.CommonName != chain[i-1].Subject.CommonName) {
				return fmt.Errorf("Subject %s Issued by Issuer=%s, expected %s",c.Subject,c.Issuer,chain[i-1].Issuer)
			}
			if ((oid != nil) && (certMissingOID(c,*oid))) {
				return fmt.Errorf("VerifyDelegate Chain Validation error - %s no oid %s\n",c,oid)
			}
		} else {
			fmt.Printf("%d: Subject=%s Issuer=%s IsCA=%v KeyUsage=%s NOCHECK\n",i,c.Subject,c.Issuer,c.IsCA,KeyUsageToString(c.KeyUsage))
		}
	}

	return nil
}

// This is a helper function, but also used in the verification process
func GenerateDelegate(key crypto.Signer, flags uint8, delegateKey crypto.PublicKey,subject string,issuer string) (*x509.Certificate, error) {
		parent := &x509.Certificate{
			SerialNumber:          big.NewInt(2),
			Subject:               pkix.Name{CommonName: issuer},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(30 * 24 * time.Hour),
			BasicConstraintsValid: true,
			KeyUsage:		x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
			IsCA:			true,
			//ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			UnknownExtKeyUsage:    []asn1.ObjectIdentifier{OID_delegateOnboard,OID_delegateUpload,OID_delegateRedirect},
		}
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: subject},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(30 * 24 * time.Hour),
			BasicConstraintsValid: true,
			IsCA:			false,
			KeyUsage:		x509.KeyUsageDigitalSignature,
			//ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			UnknownExtKeyUsage:    []asn1.ObjectIdentifier{OID_delegateOnboard,OID_delegateUpload,OID_delegateRedirect},
		}
		if (flags & (DelegateFlagIntermediate | DelegateFlagRoot))!= 0 {
			template.KeyUsage |= x509.KeyUsageCertSign 
			template.IsCA = true
		}
		
		if (flags & (DelegateFlagLeaf)) != 0 {
			template.KeyUsage |= x509.KeyUsageKeyEncipherment
		}

		der, err := x509.CreateCertificate(rand.Reader, template, parent, delegateKey, key)
		if err != nil {
			return nil, fmt.Errorf("CreateCertificate returned %v",err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		fmt.Printf(CertToString(cert,"CERTIFICATE"))


		// Let's Verify...
		derParent, err := x509.CreateCertificate(rand.Reader, parent, parent, key.Public(), key)
		certParent, err := x509.ParseCertificate(derParent)
		err = cert.CheckSignatureFrom(certParent)
		if (err != nil) { fmt.Printf("Verify error is: %w\n",err)}

		return cert, nil
}
