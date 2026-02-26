// SPDX-FileCopyrightText: (C) 2024 Intel Corporation & Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/sqlite"
)

var delegateFlags = flag.NewFlagSet("delegate", flag.ContinueOnError)

// Helper function - takes a hex byte string and
// turns it into a certificate by base64 encoding
// it and adding header/footer

func HexStringToCert(hexInput string) (string, error) {
	// Remove any whitespace or newlines from the input
	hexString := strings.ReplaceAll(string(hexInput), "\n", "")
	hexString = strings.ReplaceAll(hexString, " ", "")

	// Decode the hex string to bytes
	bytes, err := hex.DecodeString(hexString)
	if err != nil {
		return "", fmt.Errorf("failed to decode hex string: %v", err)
	}

	// Encode the bytes to base64
	base64String := base64.StdEncoding.EncodeToString(bytes)

	// Split the base64 string into lines of 64 characters
	var lines []string
	for i := 0; i < len(base64String); i += 64 {
		end := i + 64
		if end > len(base64String) {
			end = len(base64String)
		}
		lines = append(lines, base64String[i:end])
	}

	// Print the certificate with headers
	certStr := "-----BEGIN CERTIFICATE-----"
	for _, line := range lines {
		certStr += line
	}
	certStr += "-----END CERTIFICATE-----"

	return certStr, err
}

func init() {
	delegateFlags.StringVar(&dbPath, "db", "", "SQLite database file path")
	delegateFlags.StringVar(&dbPass, "db-pass", "", "SQLite database encryption-at-rest passphrase")
	delegateFlags.StringVar(&printDelegateChain, "print-delegate-chain", "", "Print delegate chain of `type` and exit")
	delegateFlags.StringVar(&printDelegatePrivKey, "print-delegate-private", "", "Print delegate private key of `type` and exit")
}

// Create delegate chains. Each chain has a name and a permission (e.g. Onboard or RV)
// Each cert in the chain has type - but the first ("leaf") one needs to be
// signed by (a specific) Owner (of a given key type)
//
//nolint:gocyclo // CLI command with multiple validation steps
func createDelegateCertificate(state *sqlite.DB, args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: delegate create {chainName} {Permission[,Permission...]} {ownerKeyType} {keyType...}")
	}
	name := args[0]

	// First one in chain is the "Owner" key in a voucher
	// Last one needs to be the one held by Onboarding Service/Server

	ownerKeyType := args[2]
	keyType, err := protocol.ParseKeyType(ownerKeyType)
	if err != nil {
		return fmt.Errorf("invalid owner key type: %q", ownerKeyType)
	}
	// For RsaPkcsKeyType/RsaPssKeyType, try 3072 first then 2048; others ignore rsaBits
	var lastPriv crypto.Signer
	switch keyType {
	case protocol.RsaPkcsKeyType, protocol.RsaPssKeyType:
		lastPriv, _, err = state.OwnerKey(context.Background(), keyType, 3072)
		if errors.Is(err, fdo.ErrNotFound) {
			lastPriv, _, err = state.OwnerKey(context.Background(), keyType, 2048)
		}
	default:
		lastPriv, _, err = state.OwnerKey(context.Background(), keyType, 0)
	}
	if err != nil {
		return fmt.Errorf("owner key of type %s does not exist", ownerKeyType)
	}

	var permissions []asn1.ObjectIdentifier
	permStrs := strings.Split(args[1], ",")
	for _, permStr := range permStrs {
		// "onboard" is a shortcut for all three onboard permissions
		if permStr == "onboard" {
			permissions = append(permissions, fdo.OIDPermitOnboardNewCred)
			permissions = append(permissions, fdo.OIDPermitOnboardReuseCred)
			permissions = append(permissions, fdo.OIDPermitOnboardFdoDisable)
			continue
		}
		oid, err := fdo.DelegateStringToOID(permStr)
		if err != nil {
			return fmt.Errorf("bad permission %q: %v", permStr, err)
		}
		permissions = append(permissions, oid)
	}

	var chain []*x509.Certificate
	issuer := fmt.Sprintf("%s_%s_Owner", name, ownerKeyType)
	keyTypes := args[3:]
	var sigAlg x509.SignatureAlgorithm
	var priv crypto.Signer
	for i, keyType := range keyTypes {
		switch keyType {
		case "ec256":
			priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case "ec384":
			priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		case "rsa2048":
			priv, err = rsa.GenerateKey(rand.Reader, 2048)
		case "rsa3072":
			sigAlg = x509.SHA384WithRSA
			priv, err = rsa.GenerateKey(rand.Reader, 3072)
		default:
			return fmt.Errorf("unknown key type: %s", keyType)
		}

		if err != nil {
			return fmt.Errorf("failed to generate %s key: %v", keyType, err)
		}

		var flags uint8
		subject := fmt.Sprintf("%s_%s_%d", name, keyType, i)
		switch {
		case i == 0:
			flags = fdo.DelegateFlagRoot
		case i == (len(keyTypes) - 1):
			flags = fdo.DelegateFlagLeaf
		default:
			flags = fdo.DelegateFlagIntermediate
		}
		cert, err := fdo.GenerateDelegate(lastPriv, flags, priv.Public(), subject, issuer, permissions, sigAlg)
		if err != nil {
			return fmt.Errorf("failed to generate delegate: %v", err)
		}
		lastPriv = priv
		issuer = subject
		chain = append([]*x509.Certificate{cert}, chain...)
	}

	// The last cert is the actual "delegate" cert
	// used by the server, so save it's private key
	if err := state.AddDelegateKey(name, lastPriv, chain); err != nil {
		return fmt.Errorf("failed to add delegate: %v", err)
	}
	return nil
}

// Print and validate chain (optionally against an Owner Key)
func doPrintDelegateChain(state *sqlite.DB, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("no delegate chain name specified")
	}
	var ownerPub *crypto.PublicKey
	if len(args) >= 2 {
		keyType, err := protocol.ParseKeyType(args[1])
		if err != nil {
			return fmt.Errorf("invalid owner key type: %s", args[1])
		}
		// For RsaPkcsKeyType/RsaPssKeyType, try 3072 first then 2048; others ignore rsaBits
		var ownerPriv crypto.Signer
		switch keyType {
		case protocol.RsaPkcsKeyType, protocol.RsaPssKeyType:
			ownerPriv, _, err = state.OwnerKey(context.Background(), keyType, 3072)
			if errors.Is(err, fdo.ErrNotFound) {
				ownerPriv, _, err = state.OwnerKey(context.Background(), keyType, 2048)
			}
		default:
			ownerPriv, _, err = state.OwnerKey(context.Background(), keyType, 0)
		}
		if err != nil {
			return fmt.Errorf("owner key of type %s does not exist", args[1])
		}
		op := ownerPriv.Public()
		ownerPub = &op

	}
	key, chain, err := state.DelegateKey(args[0])
	if err != nil {
		return err
	}

	fmt.Println(fdo.CertChainToString("CERTIFICATE", chain))

	fmt.Printf("Delegate Key: %s\n", fdo.KeyToString(key.Public()))
	return fdo.PrintDelegateChain(chain, ownerPub, nil)
}

func doListDelegateChains(state *sqlite.DB, _ []string) error {
	chains, err := state.ListDelegateKeys()
	if err != nil {
		return err
	}
	for _, c := range chains {
		fmt.Println(c)
	}
	return nil
}

type ECDSASignature struct {
	R *big.Int
	S *big.Int
}

func doInspectVoucher(state *sqlite.DB, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("no filename specified")
	}
	pemVoucher, err := os.ReadFile(filepath.Clean(args[0]))
	if err != nil {
		return err
	}
	blk, _ := pem.Decode(pemVoucher)
	if blk == nil {
		return fmt.Errorf("invalid PEM encoded file: %s", args[0])
	}
	if blk.Type != "OWNERSHIP VOUCHER" {
		return fmt.Errorf("expected PEM block of ownership voucher type, found %s", blk.Type)
	}
	_, err = InspectVoucher(state, blk.Bytes)
	return err
}

// InspectVoucherResult contains the results of voucher inspection
type InspectVoucherResult struct {
	OwnerKey   *crypto.PublicKey
	PrivateKey crypto.Signer // Device's private key for decryption
}

func InspectVoucher(state *sqlite.DB, voucherData []byte) (*crypto.PublicKey, error) {
	result, err := InspectVoucherFull(state, voucherData)
	if err != nil {
		return nil, err
	}
	return result.OwnerKey, nil
}

func InspectVoucherFull(state *sqlite.DB, voucherData []byte) (*InspectVoucherResult, error) {
	var ov fdo.Voucher
	if err := cbor.Unmarshal(voucherData, &ov); err != nil {
		return nil, fmt.Errorf("error parsing voucher: %w", err)
	}
	//fmt.Printf("RAW BYES: %s\n",hex.EncodeToString(blk.Bytes))
	fmt.Printf("Version         :    %d\n", ov.Version)
	//fmt.Printf("Header          :    %+v\n",ov.Header)
	header := ov.Header
	fmt.Printf("Header :    %+v\n", header)
	fmt.Printf("Header :    %T\n", header.Val.Version)

	fmt.Printf("GUID            : %s\n", header.Val.GUID)
	fmt.Printf("RvInfo          : \n")
	for i, rv := range header.Val.RvInfo {
		for ii, rvv := range rv {
			fmt.Printf("   %d/%d: %d \"%s\"\n", i, ii, rvv.Variable, rvv.Value)
		}
	}
	fmt.Printf("DeviceInfo      :    %s\n", header.Val.DeviceInfo)
	fmt.Printf("ManufKey        :    %v\n", header.Val.ManufacturerKey)
	fmt.Printf("CertChainHash   :    %s\n", header.Val.CertChainHash)
	fmt.Printf("Hmac            :    %s\n", ov.Hmac)
	for i, cert := range *ov.CertChain {
		fmt.Printf("CertChain      %d: %s Issuer: %s\n", i, cert.Subject, cert.Issuer)
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		pemBytes := pem.EncodeToMemory(pemBlock)
		fmt.Printf("%s\n", pemBytes)
	}
	//fmt.Printf("Entries    :    %v\n",ov.Entries)
	for i, e := range ov.Entries {
		fmt.Printf("======== ENTRY %d ==========\n", i)
		//fmt.Printf("Entry Payload  %d: %+v \n",i,e.Payload)
		chain, _ := e.Payload.Val.PublicKey.Chain()
		//fmt.Printf("Entry Chain Size %d\n",len(chain))
		fmt.Printf("Entry PubKey %v\n", e.Payload.Val.PublicKey)
		for c, cert := range chain {
			fmt.Printf("Entry Chain    %d -- %d: %s \n", i, c, cert.Subject.CommonName)
		}
		fmt.Printf("Entry PubKey   %d: %+v \n", i, e.Payload.Val.PublicKey)
		//fmt.Printf("Entry Extra    %d: %+v \n",i,e.Payload.Val.Extra)
		//for m := range maps.Keys(e.Payload.Val.Extra.Val) {
		//fmt.Printf("Entry Extra Key    %d -- %T %+v\n",m,e.Payload.Val.Extra.Val[m],e.Payload.Val.Extra.Val[m])
		//}
		dExtra, ok := e.Payload.Val.Extra.Val[-65537]
		if ok {
			//fmt.Printf("Entry DellX    %d: %s \n",i,dExtra)
			//fmt.Printf("Extra: %s\n",hex.EncodeToString(dExtra))
			var got map[string]any
			if err := cbor.Unmarshal(dExtra, &got); err == nil {
				//fmt.Printf("Extra: %T %+v\n",got,got)
				for k, v := range got {
					//fmt.Printf("   ------- Extra %s %T -- %+v\n",k,v,v)
					if vmap, ok := v.(map[any]any); ok {
						for kk, vv := range vmap {
							fmt.Printf("   ------- Extra %s - %s %T -- %+v\n", k, kk, vv, vv)

						}
					}

				}
			}

		}
	}

	// TODO Lets try to verify?
	// RsaBits() returns 0 for EC keys (ignored by OwnerKey) and actual size for RSA keys
	ownerKey, _, _ := state.OwnerKey(context.Background(), header.Val.ManufacturerKey.Type, header.Val.ManufacturerKey.RsaBits())
	info := fdo.OvhValidationContext{
		PublicKeyToValidate: ownerKey.Public(),
	}
	dc, hmacSha256, hmacSha384, privateKey, cleanup, err := readCred()
	if err == nil && cleanup != nil {
		defer func() { _ = cleanup() }()
	}

	err = ov.VerifyCrypto(fdo.VerifyOptions{
		HmacSha256:         hmacSha256,
		HmacSha384:         hmacSha384,
		MfgPubKeyHash:      dc.PublicKeyHash,
		OwnerPubToValidate: info.PublicKeyToValidate,
		To1d:               nil,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to validate voucher: %w", err)
	}
	ownerPublic := ownerKey.Public()
	return &InspectVoucherResult{
		OwnerKey:   &ownerPublic,
		PrivateKey: privateKey,
	}, nil
}
func doPrintDelegatePrivKey(state *sqlite.DB, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("no delegate chain name specified")
	}
	var pemBlock *pem.Block
	key, _, err := state.DelegateKey(args[0])
	if err != nil {
		return err
	}

	// Private Key
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
			return err
		}
		pemBlock = &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: der,
		}

	default:
		err = fmt.Errorf("unknown owner key type %T", key)
		return err
	}

	return pem.Encode(os.Stdout, pemBlock)
}

// doGenerateCSR generates a keypair and CSR for delegate certificate issuance.
// The requester runs this command, sends the CSR to the owner-key holder for signing.
// Usage: delegate generate-csr <subject-CN> <key-type> [-key-out <path>]
//
//nolint:gocyclo // CLI command with multiple validation steps
func doGenerateCSR(_ *sqlite.DB, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: delegate generate-csr <subject-CN> <key-type> [-key-out <path>]")
	}
	subject := args[0]
	keyTypeName := args[1]

	// Parse optional -key-out flag from remaining args
	keyOutPath := subject + ".key.pem"
	for i := 2; i < len(args)-1; i++ {
		if args[i] == "-key-out" {
			keyOutPath = args[i+1]
		}
	}

	// Generate keypair
	var priv crypto.Signer
	var err error
	switch keyTypeName {
	case "ec256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ec384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "rsa2048":
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	case "rsa3072":
		priv, err = rsa.GenerateKey(rand.Reader, 3072)
	default:
		return fmt.Errorf("unknown key type %q (use ec256, ec384, rsa2048, rsa3072)", keyTypeName)
	}
	if err != nil {
		return fmt.Errorf("failed to generate %s key: %v", keyTypeName, err)
	}

	// Create CSR
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: subject},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, priv)
	if err != nil {
		return fmt.Errorf("failed to create CSR: %v", err)
	}

	// Verify CSR is well-formed
	if _, err := x509.ParseCertificateRequest(csrDER); err != nil {
		return fmt.Errorf("failed to parse generated CSR: %v", err)
	}

	// Save private key to file
	keyPEM, err := marshalPrivateKeyPEM(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %v", err)
	}
	if err := os.WriteFile(keyOutPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("failed to write private key to %s: %v", keyOutPath, err)
	}
	fmt.Fprintf(os.Stderr, "Private key saved to: %s\n", keyOutPath)

	// Write CSR PEM to stdout
	return pem.Encode(os.Stdout, &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})
}

// doSignCSR signs a CSR using the local owner key, producing a delegate certificate
// with scoped permissions. The owner-key holder runs this command.
// Usage: delegate sign-csr <csr-file> <chain-name> <permissions> <owner-key-type> [-db <db>]
//
//nolint:gocyclo // CLI command with multiple validation steps
func doSignCSR(state *sqlite.DB, args []string) error {
	if len(args) < 4 {
		return fmt.Errorf("usage: delegate sign-csr <csr-file> <chain-name> <permissions> <owner-key-type>")
	}
	csrFile := args[0]
	chainName := args[1]
	permStr := args[2]
	ownerKeyType := args[3]

	// Read and parse CSR
	csrPEM, err := os.ReadFile(filepath.Clean(csrFile))
	if err != nil {
		return fmt.Errorf("failed to read CSR file %s: %v", csrFile, err)
	}
	blk, _ := pem.Decode(csrPEM)
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		return fmt.Errorf("expected PEM block of type CERTIFICATE REQUEST in %s", csrFile)
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("CSR signature verification failed: %v", err)
	}

	// Load owner key from DB
	keyType, err := protocol.ParseKeyType(ownerKeyType)
	if err != nil {
		return fmt.Errorf("invalid owner key type: %q", ownerKeyType)
	}
	var ownerPriv crypto.Signer
	switch keyType {
	case protocol.RsaPkcsKeyType, protocol.RsaPssKeyType:
		ownerPriv, _, err = state.OwnerKey(context.Background(), keyType, 3072)
		if errors.Is(err, fdo.ErrNotFound) {
			ownerPriv, _, err = state.OwnerKey(context.Background(), keyType, 2048)
		}
	default:
		ownerPriv, _, err = state.OwnerKey(context.Background(), keyType, 0)
	}
	if err != nil {
		return fmt.Errorf("owner key of type %s does not exist: %v", ownerKeyType, err)
	}

	// Parse permissions
	var permissions []asn1.ObjectIdentifier
	permStrs := strings.Split(permStr, ",")
	for _, ps := range permStrs {
		if ps == "onboard" {
			permissions = append(permissions, fdo.OIDPermitOnboardNewCred)
			permissions = append(permissions, fdo.OIDPermitOnboardReuseCred)
			permissions = append(permissions, fdo.OIDPermitOnboardFdoDisable)
			continue
		}
		oid, err := fdo.DelegateStringToOID(ps)
		if err != nil {
			return fmt.Errorf("bad permission %q: %v", ps, err)
		}
		permissions = append(permissions, oid)
	}

	// Generate delegate certificate using the CSR's public key
	cert, err := fdo.GenerateDelegate(
		ownerPriv,
		fdo.DelegateFlagLeaf,
		csr.PublicKey,
		csr.Subject.CommonName,
		fmt.Sprintf("%s_%s_Owner", chainName, ownerKeyType),
		permissions,
		0,
	)
	if err != nil {
		return fmt.Errorf("failed to generate delegate certificate: %v", err)
	}

	chain := []*x509.Certificate{cert}

	// Store cert-only in DB (no private key — the requester holds that)
	// We use a nil private key placeholder; AddDelegateKey requires a key,
	// so we store the owner key as a placeholder for inspection purposes.
	// The actual delegate private key is held by the requester.
	if err := state.AddDelegateKey(chainName, ownerPriv, chain); err != nil {
		return fmt.Errorf("failed to store delegate chain %q: %v", chainName, err)
	}
	fmt.Fprintf(os.Stderr, "Delegate chain %q stored in database (cert-only, requester holds private key)\n", chainName)

	// Output signed cert chain PEM to stdout
	return pem.Encode(os.Stdout, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// doImportCert imports a signed delegate cert chain and pairs it with a local private key.
// The requester runs this command after receiving the signed cert back from the owner-key holder.
// Usage: delegate import-cert <chain-name> <cert-chain.pem> <private-key.pem> [-db <db>]
func doImportCert(state *sqlite.DB, args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: delegate import-cert <chain-name> <cert-chain.pem> <private-key.pem>")
	}
	chainName := args[0]
	certFile := args[1]
	keyFile := args[2]

	// Read and parse cert chain
	certPEM, err := os.ReadFile(filepath.Clean(certFile))
	if err != nil {
		return fmt.Errorf("failed to read cert file %s: %v", certFile, err)
	}
	var chain []*x509.Certificate
	rest := certPEM
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %v", err)
		}
		chain = append(chain, cert)
	}
	if len(chain) == 0 {
		return fmt.Errorf("no certificates found in %s", certFile)
	}

	// Read and parse private key
	keyPEM, err := os.ReadFile(filepath.Clean(keyFile))
	if err != nil {
		return fmt.Errorf("failed to read key file %s: %v", keyFile, err)
	}
	privKey, err := parsePrivateKeyPEM(keyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse private key from %s: %v", keyFile, err)
	}

	// Validate that the leaf cert's public key matches the private key
	leaf := chain[0] // leaf is first in chain (same convention as delegate create)
	if !publicKeysEqual(leaf.PublicKey, privKey.Public()) {
		return fmt.Errorf("leaf certificate public key does not match private key")
	}

	// Store in DB
	if err := state.AddDelegateKey(chainName, privKey, chain); err != nil {
		return fmt.Errorf("failed to store delegate chain %q: %v", chainName, err)
	}
	fmt.Fprintf(os.Stderr, "Delegate chain %q imported (%d cert(s) + private key)\n", chainName, len(chain))
	return nil
}

// marshalPrivateKeyPEM encodes a private key as PEM.
func marshalPrivateKeyPEM(key crypto.Signer) ([]byte, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
	case *rsa.PrivateKey:
		der := x509.MarshalPKCS1PrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}), nil
	default:
		return nil, fmt.Errorf("unsupported key type %T", key)
	}
}

// parsePrivateKeyPEM parses a PEM-encoded private key (EC or RSA).
func parsePrivateKeyPEM(pemData []byte) (crypto.Signer, error) {
	blk, _ := pem.Decode(pemData)
	if blk == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	switch blk.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(blk.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(blk.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("PKCS8 key is not a signer")
		}
		return signer, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", blk.Type)
	}
}

// publicKeysEqual compares two public keys for equality.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	switch ak := a.(type) {
	case *ecdsa.PublicKey:
		bk, ok := b.(*ecdsa.PublicKey)
		return ok && ak.Equal(bk)
	case *rsa.PublicKey:
		bk, ok := b.(*rsa.PublicKey)
		return ok && ak.Equal(bk)
	default:
		return false
	}
}

func doDelegateHelp(_ *sqlite.DB, _ []string) error {
	fmt.Printf(`
Delegate commands:

  --- Quick single-party (generates key+cert together, for testing) ---
  delegate create {chainName} {Permission[,Permission...]} {ownerKeyType} {keyType} [keyType...]

  --- Multi-party CSR workflow (for production) ---
  delegate generate-csr {subject-CN} {key-type} [-key-out {path}]
  delegate sign-csr {csr-file} {chain-name} {permissions} {owner-key-type}
  delegate import-cert {chain-name} {cert-chain.pem} {private-key.pem}

  --- Inspection ---
  delegate print {chainname} [ownerKeyType]
  delegate list
  delegate key {chainname}
  delegate inspectVoucher {filename}

Permissions:
  voucher-claim        - Claim (pull/download) vouchers via PullAuth
  onboard              - All onboard permissions (new-cred, reuse-cred, fdo-disable)
  redirect             - Redirect permission (TO0)
  onboard-new-cred     - Onboard with new credentials
  onboard-reuse-cred   - Onboard with credential reuse
  onboard-fdo-disable  - Onboard and disable FDO
  claim                - Legacy claim permission
  provision            - Legacy provision permission

KeyTypes: ec256, ec384, rsa2048, rsa3072
OwnerKeyTypes: SECP384R1, SECP256R1, RSA2048RESTR, RSAPKCS, RSAPSS

CSR Workflow:
  1. Requester: delegate generate-csr myService ec384 -key-out myService.key.pem > myService.csr.pem
  2. Owner:     delegate sign-csr myService.csr.pem myDelegate voucher-claim SECP384R1 > signed.pem
  3. Requester: delegate import-cert myDelegate signed.pem myService.key.pem

`)
	return nil
}

//nolint:gocyclo
func delegate(args []string) error {
	if debug {
		level.Set(slog.LevelDebug)
	}

	if len(args) < 1 {
		return errors.New("command required")
	}

	// Commands that don't require a database
	switch args[0] {
	case "generate-csr":
		return doGenerateCSR(nil, args[1:])
	case "help":
		return doDelegateHelp(nil, args[1:])
	}

	if dbPath == "" {
		return errors.New("db flag is required")
	}

	state, err := sqlite.Open(dbPath, dbPass)
	if err != nil {
		return err
	}

	switch args[0] {
	case "list":
		return doListDelegateChains(state, args[1:])
	case "print":
		return doPrintDelegateChain(state, args[1:])
	case "key":
		return doPrintDelegatePrivKey(state, args[1:])
	case "create":
		return createDelegateCertificate(state, args[1:])
	case "sign-csr":
		return doSignCSR(state, args[1:])
	case "import-cert":
		return doImportCert(state, args[1:])
	case "inspectVoucher":
		return doInspectVoucher(state, args[1:])
	default:
		return fmt.Errorf("invalid command %q", args[0])
	}
}
