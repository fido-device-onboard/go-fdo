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

	//"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	_ "encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log/slog"
	_ "maps"
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

var ()

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
		return "", fmt.Errorf("Failed to decode hex string: %v", err)
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

// Create delegage chains. Each chane has a name and a persmission (e.g. Onboard or RV)
// Each cert in the chain has type - but the first ("leaf") one needs to be
// signed by (a specific) Owner (of a given key type)
func createDelegateCertificate(state *sqlite.DB, args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("Usage: delegate create {chainName} {Permission[,Permission...]} {ownerKeyType} {keyType...}")
	}
	name := args[0]

	// First one in chain is the "Owner" key in a voucher
	// Last one needs to be the one held by Onboarding Service/Server

	ownerKeyType := args[2]
	keyType, err := protocol.ParseKeyType(ownerKeyType)
	if err != nil {
		return fmt.Errorf("Invalid owner key type: \"%s\"", ownerKeyType)
	}
	lastPriv, _, err := state.OwnerKey(context.Background(), keyType, 0)
	if err != nil {
		return fmt.Errorf("Owner Key of type %s does not exist", ownerKeyType)
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
			return fmt.Errorf("Bad Permission \"%s\": %v", permStr, err)
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
			return fmt.Errorf("Failed to generate %s key: %v\n", keyType, err)
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
			return fmt.Errorf("Failed to generate Delegate: %v\n", err)
		}
		lastPriv = priv
		issuer = subject
		chain = append([]*x509.Certificate{cert}, chain...)
	}

	// The last cert is the actual "delegate" cert
	// used by the server, so save it's private key
	if err := state.AddDelegateKey(name, lastPriv, chain); err != nil {
		return fmt.Errorf("Failed to add Delegate: %v\n", err)
	}
	return nil
}

// Print and validate chain (optinally against an Owner Key)
func doPrintDelegateChain(state *sqlite.DB, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("No delegate chain name specified")
	}
	var ownerPub *crypto.PublicKey
	if len(args) >= 2 {
		keyType, err := protocol.ParseKeyType(args[1])
		if err != nil {
			return fmt.Errorf("Invalid owner key type: %s", args[1])
		}

		ownerPriv, _, err := state.OwnerKey(context.Background(), keyType, 0)
		if err != nil {
			return fmt.Errorf("Owner Key of type %s does not exist", args[1])
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

func doAttestPayload(state *sqlite.DB, args []string) error {
	pemData, err := ioutil.ReadFile(filepath.Clean(args[0]))
	if err != nil {
		return fmt.Errorf("failed to read PEM file: %w", err)
	}

	//var blocks []*pem.Block
	voucherError := fmt.Errorf("NoVoucher")
	var payload []byte
	var ownerKey *crypto.PublicKey
	var sigbytes []byte
	var delegateChain []*x509.Certificate
	for {
		block, rest := pem.Decode(pemData)
		if block == nil {
			break // No more PEM blocks found
		}
		fmt.Printf("Block \"%s\"  -  %d bytes\n", block.Type, len(block.Bytes))
		switch block.Type {
		case "OWNERSHIP VOUCHER":
			var oKey *crypto.PublicKey
			oKey, voucherError = InspectVoucher(state, block.Bytes)
			if voucherError != nil {
				return fmt.Errorf("InspectVoucher failed: %w", voucherError)
			}
			ownerKey = oKey

		case "IV":
			fmt.Printf("IV Data %x\n", block.Bytes)
		case "CIPHERTEXT":
			fmt.Printf("Cyphertext Data %x\n", block.Bytes)
		case "WRAPPED ENCRYPTION KEY":
			fmt.Printf("Wrapped Encryption Key %x\n", block.Bytes)

		case "PAYLOAD":
			payload = block.Bytes

		case "SIGNATURE":
			sigbytes = block.Bytes

		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return err
			}
			fmt.Printf("DELEGATE CERT \"%s\"  -  %d bytes\n", block.Type, len(block.Bytes))
			delegateChain = append(delegateChain, cert)
		default:
			fmt.Printf("Unknown Block %s\n", block.Type)
		}
		pemData = rest
	}
	fmt.Printf("VoucherError: %v\n", voucherError)
	fmt.Printf("OwnerKey: %v\n", ownerKey)
	if voucherError != nil {
		return voucherError
	}
	fmt.Printf("Payload: \"%s\"\n", string(payload))
	if ownerKey == nil {
		return fmt.Errorf("No Owner Key")
	}
	hashed := sha512.Sum384(payload)

	// Do we need to validate against delegate chain??
	if len(delegateChain) > 0 {
		/* Delegates can only sign payloads when they have "Provision" permission */
		err = fdo.VerifyDelegateChain(delegateChain, ownerKey, &fdo.OIDDelegateProvision)
		if err != nil {
			return fmt.Errorf("VerifyDelegateChain failed: %w", err)
		}
		//ownerKey = delegagateLeaf....
		fmt.Printf("Delegate Leaf is %T\n", delegateChain[0].PublicKey)
		switch pub := delegateChain[0].PublicKey.(type) {
		case *ecdsa.PublicKey:
			var temp crypto.PublicKey = *pub
			ownerKey = &temp
			fmt.Printf("New Owner is %T %v+", ownerKey, ownerKey)
		default:
			return fmt.Errorf("Invalid delegate leaf key type %T", pub)
		}
	}

	/* TODO - supports sha384/ecdsa384 only */
	fmt.Printf("OwnerKey type is %T\n", ownerKey)
	switch pub := (*ownerKey).(type) {
	case *rsa.PublicKey:
		//h := sha512.Sum384(payload)
		err := rsa.VerifyPKCS1v15(pub, crypto.SHA384, hashed[:], sigbytes)
		if err != nil {
			return fmt.Errorf("RSA Signature verify failed %w", err)
		}
		//fmt.Printf("RSA Sig Verify of %v+ sig %v returns %w\n",h,sigbytes,err)
	case *ecdsa.PublicKey:
		sig := new(ECDSASignature)
		_, err := asn1.Unmarshal(sigbytes, sig)
		if err != nil {
			return fmt.Errorf("failed to unmarshal ASN.1 ECDSA signature: %w", err)
		}
		fmt.Printf("Signature is %v+\n", sig)
		verified := ecdsa.Verify(pub, hashed[:], sig.R, sig.S)
		fmt.Printf("ECDSA ptr Verify returned %v\n", verified)
		if !verified {
			return fmt.Errorf("ECDSA Signature verification FAILED")
		}
	case ecdsa.PublicKey:
		sig := new(ECDSASignature)
		_, err := asn1.Unmarshal(sigbytes, sig)
		if err != nil {
			return fmt.Errorf("failed to unmarshal ASN.1 ECDSA signature: %w", err)
		}
		fmt.Printf("Signature is %v+\n", sig)
		verified := ecdsa.Verify(&pub, hashed[:], sig.R, sig.S)
		fmt.Printf("ECDSA Verify returned %v\n", verified)
		if !verified {
			return fmt.Errorf("ECDSA Signature verification FAILED")
		}
	default:
		return fmt.Errorf("Bad Owner Key Type %T", pub)
	}

	fmt.Println(string(payload))
	return nil
}

func doInspectVoucher(state *sqlite.DB, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("No filename specified")
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

func InspectVoucher(state *sqlite.DB, voucherData []byte) (*crypto.PublicKey, error) {
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
	ownerKey, _, err := state.OwnerKey(context.Background(), header.Val.ManufacturerKey.Type, 0)
	var info fdo.OvhValidationContext = fdo.OvhValidationContext{
		PublicKeyToValidate: ownerKey.Public(),
	}
	dc, hmacSha256, hmacSha384, privateKey, cleanup, err := readCred()
	if err == nil && cleanup != nil {
		defer func() { _ = cleanup() }()
	}

	_ = privateKey // TODO BKG FIX We will need to decrypt attested Payload
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
	//fmt.Printf("%+v\n",ov)
	ownerPublic := ownerKey.Public()
	return &ownerPublic, err
}
func doPrintDelegatePrivKey(state *sqlite.DB, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("No delegate chain name specified")
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
		err = fmt.Errorf("Unknown Owner key type %T", key)
		return err
	}

	return pem.Encode(os.Stdout, pemBlock)
}

func doDelegateHelp(_ *sqlite.DB, _ []string) error {
	fmt.Printf(`
Delegate commands:

delegate print {chainname} [ownerKeyType]
delegate list
delegate key {chainname} 
delegate inspectVoucher {filename} 
delegate attestPayload {filename} 
delegate create {chainName} {Permission[,Permission...]} {ownerKeyType} {keyType} [keyType...]

Permissions:
  onboard              - All onboard permissions (new-cred, reuse-cred, fdo-disable)
  redirect             - Redirect permission (TO0)
  onboard-new-cred     - Onboard with new credentials
  onboard-reuse-cred   - Onboard with credential reuse
  onboard-fdo-disable  - Onboard and disable FDO
  claim                - Claim permission
  provision            - Provision permission
KeyTypes: ec256, ec384, rsa2048, rsa3072
ownerKeyTypes - See "Key types"


`)
	return nil
}

//nolint:gocyclo
func delegate(args []string) error {
	if debug {
		level.Set(slog.LevelDebug)
	}

	if dbPath == "" {
		return errors.New("db flag is required")
	}

	if len(args) < 1 {
		return errors.New("command requried")
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
	case "inspectVoucher":
		return doInspectVoucher(state, args[1:])
	case "attestPayload":
		return doAttestPayload(state, args[1:])
	case "help":
		return doDelegateHelp(state, args[1:])
	default:
		return fmt.Errorf("Invalid command \"%s\"", args[0])
	}
}
