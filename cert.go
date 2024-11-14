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

type stringOrNull interface {
}
