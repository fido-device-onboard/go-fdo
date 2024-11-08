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
