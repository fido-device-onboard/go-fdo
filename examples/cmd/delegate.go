// SPDX-FileCopyrightText: (C) 2024 Intel Corporation & Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
        "crypto"
        "crypto/ecdsa"
        "crypto/rsa"
        "crypto/rand"
        "crypto/elliptic"
        "crypto/x509"
        "encoding/asn1"
        "encoding/pem"
        _ "encoding/hex"
        "errors"
        "flag"
        "fmt"
        "log/slog"
        "os"
        "strings"
        "encoding/hex"
        "encoding/base64"
	"path/filepath"
	_ "maps"

        "github.com/fido-device-onboard/go-fdo"
        "github.com/fido-device-onboard/go-fdo/protocol"
        "github.com/fido-device-onboard/go-fdo/sqlite"
	"github.com/fido-device-onboard/go-fdo/cbor"
)

var delegateFlags = flag.NewFlagSet("delegate", flag.ContinueOnError)

var (
)

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
        return "",fmt.Errorf("Failed to decode hex string: %v", err)
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

    return certStr,err
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
func createDelegateCertificate(state *sqlite.DB,args []string) error {
        if (len(args) < 3) {
                return fmt.Errorf("Usage: delegate create {chainName} {Permission[,Permission...]} {ownerKeyType} {keyType...}")
        }
        name := args[0]

        // First one in chain is the "Owner" key in a voucher
        // Last one needs to be the one held by Onboarding Service/Server

        ownerKeyType := args[2]
        keyType, err := protocol.ParseKeyType(ownerKeyType)
        if (err != nil) {
                return fmt.Errorf("Invalid owner key type: \"%s\"",ownerKeyType)
        }
        lastPriv, lastCert, err := state.OwnerKey(keyType)
        if (err != nil) {
                return fmt.Errorf("Owner Key of type %s does not exist",ownerKeyType)
        }

	fmt.Printf("** GOT OLD CERT %+v\n",lastCert[0])

        var permissions []asn1.ObjectIdentifier
        permStrs := strings.Split(args[1],",")
        for _, permStr := range permStrs {
                oid, err := fdo.DelegateStringToOID(permStr)
                if (err != nil) {
                        return fmt.Errorf("Bad Permission \"%s\": %v",permStr,err)
                }
                permissions = append(permissions,oid)
        }

        var chain []*x509.Certificate 
        issuer := fmt.Sprintf("%s_%s_Owner",name,ownerKeyType)
        keyTypes := args[3:]
        var sigAlg x509.SignatureAlgorithm
        var priv crypto.Signer
        for i,keyType := range keyTypes {
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
                        return fmt.Errorf("Failed to generate %s key: %v\n",keyType,err)
                }

                var flags uint8
                subject := fmt.Sprintf("%s_%s_%d",name,keyType,i)
                switch  {
                        case i == 0:
                                flags = fdo.DelegateFlagRoot
                        case i == (len(keyTypes)-1):
                                flags = fdo.DelegateFlagLeaf
                        default:
                                flags = fdo.DelegateFlagIntermediate
                }
                fmt.Printf("Generate Key Type %s\n",keyType)
                cert, err := fdo.GenerateDelegate(lastPriv,flags,priv.Public(),subject,issuer,permissions, sigAlg)
                if err != nil {
                        return fmt.Errorf("Failed to generate Delegate: %v\n",err)
                }
                fmt.Printf("%d: Subject=%s Issuer=%s IsCA=%v KeyUsage=%v\n",i,cert.Subject,cert.Issuer,cert.IsCA,cert.KeyUsage)
                lastPriv=priv
                issuer = subject
                chain = append([]*x509.Certificate{cert},chain...)
        }

        // The last cert is the actual "delegate" cert
        // used by the server, so save it's private key
        if err := state.AddDelegateKey(name, lastPriv, chain); err != nil {
                return fmt.Errorf("Failed to add Delegate: %v\n",err)
        }
        return nil
}

// Print and validate chain (optinally against an Owner Key)
func doPrintDelegateChain(state *sqlite.DB,args []string) error {
        if (len(args) < 1) {
                return fmt.Errorf("No delegate chain name specified")
        }
        var ownerPub *crypto.PublicKey
        if (len(args) >=2 ) {
                keyType, err := protocol.ParseKeyType(args[1])
                if (err != nil) {
                        return fmt.Errorf("Invalid owner key type: %s",args[1])
                }

                ownerPriv, _, err := state.OwnerKey(keyType)
                if (err != nil) {
                        return fmt.Errorf("Owner Key of type %s does not exist",args[1])
                }
                op :=ownerPriv.Public()
                ownerPub = &op

        }
        key, chain, err := state.DelegateKey(args[0])
        if err != nil {
                return err
        }

        fmt.Println(fdo.CertChainToString("CERTIFICATE",chain))

        fmt.Printf("Delegate Key: %s\n",fdo.KeyToString(key.Public()))
        return fdo.VerifyDelegateChain(chain,ownerPub,nil)

        return nil
}

func doListDelegateChains(state *sqlite.DB,args []string) error {
        chains, err := state.ListDelegateKeys()
        if err != nil {
                return err
        }
        for _,c := range chains {
                fmt.Println(c)
        }
        return nil
}


func doInspectVoucher(state *sqlite.DB,args []string) error {
	// Parse voucher
        if (len(args) < 1) {
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
	var ov fdo.Voucher
	if err := cbor.Unmarshal(blk.Bytes, &ov); err != nil {
		return fmt.Errorf("error parsing voucher: %w", err)
	}
	//fmt.Printf("RAW BYES: %s\n",hex.EncodeToString(blk.Bytes))
	fmt.Printf("Version         :    %d\n",ov.Version)
	//fmt.Printf("Header          :    %+v\n",ov.Header)
	header := ov.Header
	fmt.Printf("Header :    %+v\n",header)
	fmt.Printf("Header :    %T\n",header.Val.Version)
	
	fmt.Printf("GUID            : %s\n",header.Val.GUID)
	fmt.Printf("RvInfo          : \n")
	for i,rv := range header.Val.RvInfo {
		for ii,rvv := range rv {
			fmt.Printf("   %d/%d: %d \"%s\"\n",i,ii,rvv.Variable,rvv.Value)
		}
	}
	fmt.Printf("DeviceInfo      :    %s\n",header.Val.DeviceInfo)
	fmt.Printf("ManufKey        :    %v\n",header.Val.ManufacturerKey)
	fmt.Printf("CertChainHash   :    %s\n",header.Val.CertChainHash)
	fmt.Printf("Hmac            :    %s\n",ov.Hmac)
	for i,cert := range *ov.CertChain {
		fmt.Printf("CertChain      %d: %s Issuer: %s\n",i,cert.Subject,cert.Issuer)
		pemBlock := &pem.Block{
			Type: "CERTIFICATE",
			Bytes: cert.Raw,
		}
		pemBytes := pem.EncodeToMemory(pemBlock)
		fmt.Printf("%s\n",pemBytes)
	}
	//fmt.Printf("Entries    :    %v\n",ov.Entries)
	for i,e := range ov.Entries {
		fmt.Printf("======== ENTRY %d ==========\n",i)
		//fmt.Printf("Entry Payload  %d: %+v \n",i,e.Payload)
		chain,_ := e.Payload.Val.PublicKey.Chain()
		//fmt.Printf("Entry Chain Size %d\n",len(chain))
		fmt.Printf("Entry PubKey %v\n", e.Payload.Val.PublicKey)
		for c,ii := range chain {
			fmt.Printf("Entry Chain    %d -- %d: %T \n",i,ii,c)
		}
		fmt.Printf("Entry PubKey   %d: %+v \n",i, e.Payload.Val.PublicKey)
		//fmt.Printf("Entry Extra    %d: %+v \n",i,e.Payload.Val.Extra)
		//for m := range maps.Keys(e.Payload.Val.Extra.Val) {
			//fmt.Printf("Entry Extra Key    %d -- %T %+v\n",m,e.Payload.Val.Extra.Val[m],e.Payload.Val.Extra.Val[m])
		//}
		dExtra,ok := e.Payload.Val.Extra.Val[-65537]
		if (ok) {
			//fmt.Printf("Entry DellX    %d: %s \n",i,dExtra)
			//fmt.Printf("Extra: %s\n",hex.EncodeToString(dExtra))
	                var got map[string]any
			if err := cbor.Unmarshal(dExtra, &got); err == nil {
				//fmt.Printf("Extra: %T %+v\n",got,got)
				for k,v := range got {
					//fmt.Printf("   ------- Extra %s %T -- %+v\n",k,v,v)
					if vmap,ok := v.(map[any]any) ; ok {
						for kk,vv := range vmap {
							fmt.Printf("   ------- Extra %s - %s %T -- %+v\n",k,kk,vv,vv)

						}
					}

				}
			} 

		}
	}
	
	//fmt.Printf("%+v\n",ov)
	return nil
}
func doPrintDelegatePrivKey(state *sqlite.DB,args []string) error {
        if (len(args) < 1) {
                return fmt.Errorf("No delegate chain name specified")
        }
        var pemBlock *pem.Block
        key, _, err := state.DelegateKey(args[0])
        if err != nil {
                return err
        }


        // Private Key
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
                                return err
                        }
                        pemBlock = &pem.Block{
                                Type:  "EC PRIVATE KEY",
                                Bytes: der,
                        }

                default:
                        err =  fmt.Errorf("Unknown Owner key type %T", key)
                        return err
        }

        return pem.Encode(os.Stdout, pemBlock)
}

func doDelegateHelp(state *sqlite.DB,args []string) error {
        fmt.Printf (`
Delegate commands:

delegate print {chainname} [ownerKeyType]
delegate list
delegate key {chainname} 
delegate inspectVoucher {filename} 
delegate create {chainName} {Permission[,Permission...]} {ownerKeyType} {keyType} [keyType...]

Permissions: onboard upload redirect claim provision
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

        if (len(args) < 1) {
                return errors.New("command requried")
        }

        state, err := sqlite.New(dbPath, dbPass)
        if err != nil {
                return err
        }

        switch args[0] {
                case "list" :
                        return doListDelegateChains(state,args[1:])
                case "print":
                        return doPrintDelegateChain(state,args[1:])
                case "key":
                        return doPrintDelegatePrivKey(state,args[1:])
                case "create":
                        return createDelegateCertificate(state,args[1:])
                case "inspectVoucher":
                        return doInspectVoucher(state,args[1:])
                case "help":
                        return doDelegateHelp(state,args[1:])
                default:
                        return fmt.Errorf("Invalid command \"%s\"",args[0])
                
        }
        return nil
}


