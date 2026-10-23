// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

//go:build (tpm || tpmsim) && !tinygo

package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/tpm"
)

// tpmClearCredentials removes all FDO NV indices and persistent handles from the TPM.
func tpmClearCredentials() error {
	tpmc, err := tpmOpen(tpmPath)
	if err != nil {
		return fmt.Errorf("opening TPM: %w", err)
	}
	defer func() { _ = tpmc.Close() }()

	source := tpmPath
	if source == "" {
		source = "default"
	}
	fmt.Printf("Clearing all FDO credentials from TPM [%s]...\n", source)
	tpm.CleanupFDOState(tpmc)
	fmt.Println("Done. All FDO NV indices and persistent keys removed.")
	return nil
}

// tpmShowCredentials reads and displays all FDO credentials stored in the consolidated DCTPM NV index.
func tpmShowCredentials() error {
	tpmc, err := tpmOpen(tpmPath)
	if err != nil {
		return fmt.Errorf("opening TPM: %w", err)
	}
	defer func() { _ = tpmc.Close() }()

	info, err := tpm.ReadNVCredentials(tpmc)
	if err != nil {
		return fmt.Errorf("reading TPM credentials: %w", err)
	}

	source := tpmPath
	if source == "" {
		source = "default"
	}
	fmt.Printf("tpm-credentials[%s]\n", source)

	if info.HasDCTPM {
		fmt.Printf("  DCTPM (0x%08X)      [%d bytes]\n", tpm.DCTPMIndex, info.DCTPMSize)

		var dctpm dctpmDisplay
		if err := cbor.Unmarshal(info.RawDCTPM, &dctpm); err != nil {
			fmt.Printf("    (decode error: %v)\n", err)
		} else {
			fmt.Printf("    Magic             0x%08X", dctpm.Magic)
			if dctpm.Magic == tpm.DCTPMMagic {
				fmt.Print(" (FDO1)")
			} else {
				fmt.Print(" (INVALID)")
			}
			fmt.Println()
			fmt.Printf("    Active            %v\n", dctpm.Active)
			fmt.Printf("    Version           %d\n", dctpm.Version)
			fmt.Printf("    DeviceInfo        %q\n", dctpm.DeviceInfo)
			fmt.Printf("    GUID              %x\n", dctpm.GUID)
			fmt.Printf("    KeyType           %s\n", dctpm.KeyType)
			fmt.Printf("    DeviceKeyHandle   0x%08X\n", dctpm.DeviceKeyHandle)
			fmt.Printf("    HMACKeyHandle     0x%08X\n", dctpm.HMACKeyHandle)
			fmt.Printf("    PublicKeyHash     alg=%d value=%s\n", dctpm.PublicKeyHash.Algorithm, hex.EncodeToString(dctpm.PublicKeyHash.Value))
			if len(dctpm.RvInfo) == 0 {
				fmt.Println("    RvInfo            (none)")
			} else {
				directives := protocol.ParseDeviceRvInfo(dctpm.RvInfo)
				for i, dir := range directives {
					fmt.Printf("    RvInfo[%d]\n", i)
					for _, u := range dir.URLs {
						fmt.Printf("      URL             %s\n", u)
					}
					if dir.Bypass {
						fmt.Println("      Bypass          true")
					}
					if dir.Delay > 0 {
						fmt.Printf("      Delay           %s\n", dir.Delay)
					}
					if len(dir.URLs) == 0 && !dir.Bypass && dir.Delay == 0 {
						fmt.Println("      (delay=0, no URL)")
					}
				}
			}
		}
	} else {
		fmt.Printf("  DCTPM (0x%08X)      [not defined]\n", tpm.DCTPMIndex)
	}

	fmt.Printf("  DAK (0x%08X)        ", tpm.DAKHandle)
	if info.HasDAK {
		pubKey, err := tpm.ReadDAKPublicKey(tpmc)
		if err != nil {
			fmt.Printf("present (error reading: %v)\n", err)
		} else {
			switch k := pubKey.(type) {
			case *ecdsa.PublicKey:
				fmt.Printf("ECC %s\n", k.Curve.Params().Name)
				fmt.Printf("    X                 %x\n", k.X.Bytes())
				fmt.Printf("    Y                 %x\n", k.Y.Bytes())
			default:
				fmt.Printf("%T\n", pubKey)
			}
		}
	} else {
		fmt.Println("not present")
	}

	fmt.Printf("  HMAC Key (0x%08X)    ", tpm.HMACKeyHandle)
	if info.HasHMACKey {
		fmt.Println("present")
	} else {
		fmt.Println("not present")
	}

	return nil
}

// tpmExportDAK exports the DAK public key as PEM to stdout.
func tpmExportDAK() error {
	tpmc, err := tpmOpen(tpmPath)
	if err != nil {
		return fmt.Errorf("opening TPM: %w", err)
	}
	defer func() { _ = tpmc.Close() }()

	pubKey, err := tpm.ReadDAKPublicKey(tpmc)
	if err != nil {
		return fmt.Errorf("reading DAK public key: %w", err)
	}

	der, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("marshaling public key: %w", err)
	}

	return pem.Encode(os.Stdout, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
}

// tpmProveDAK proves possession of the DAK private key by signing a challenge.
func tpmProveDAK() error {
	tpmc, err := tpmOpen(tpmPath)
	if err != nil {
		return fmt.Errorf("opening TPM: %w", err)
	}
	defer func() { _ = tpmc.Close() }()

	var challenge []byte
	if tpmChallenge != "" {
		challenge = []byte(tpmChallenge)
	}

	proof, err := tpm.ProveDAKPossession(tpmc, challenge)
	if err != nil {
		return fmt.Errorf("DAK proof: %w", err)
	}

	switch k := proof.PublicKey.(type) {
	case *ecdsa.PublicKey:
		fmt.Printf("DAK Public Key:  ECC %s\n", k.Curve.Params().Name)
		fmt.Printf("  X:             %x\n", k.X.Bytes())
		fmt.Printf("  Y:             %x\n", k.Y.Bytes())
	default:
		fmt.Printf("DAK Public Key:  %T\n", proof.PublicKey)
	}
	fmt.Printf("Challenge:       %x\n", proof.Challenge)
	fmt.Printf("Signature:       %x\n", proof.Signature)

	// Self-verify
	ecKey, ok := proof.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		fmt.Println("Verified:        (cannot self-verify non-ECC key)")
		return nil
	}
	verified := ecdsa.VerifyASN1(ecKey, proof.Challenge[:], proof.Signature)
	fmt.Printf("Verified:        %v\n", verified)

	if !verified {
		return fmt.Errorf("self-verification failed")
	}

	sigHex := hex.EncodeToString(proof.Signature)
	chalHex := hex.EncodeToString(proof.Challenge[:])
	fmt.Println()
	fmt.Println("To verify externally:")
	fmt.Printf("  echo -n '%s' | xxd -r -p > /tmp/sig.bin\n", sigHex)
	fmt.Printf("  echo -n '%s' | xxd -r -p > /tmp/digest.bin\n", chalHex)
	fmt.Println("  # Verify with: openssl pkeyutl -verify -pubin -inkey dak.pem -in /tmp/digest.bin -sigfile /tmp/sig.bin")

	return nil
}

// dctpmDisplay mirrors the CBOR structure stored in the consolidated DCTPM NV index.
// Defined here (rather than importing from cred) because the cred package
// type is unexported and requires a build tag.
type dctpmDisplay struct {
	Magic           uint32                     `cbor:"0,keyasint"`
	Active          bool                       `cbor:"1,keyasint"`
	Version         uint16                     `cbor:"2,keyasint"`
	DeviceInfo      string                     `cbor:"3,keyasint"`
	GUID            protocol.GUID              `cbor:"4,keyasint"`
	RvInfo          [][]protocol.RvInstruction `cbor:"5,keyasint"`
	PublicKeyHash   protocol.Hash              `cbor:"6,keyasint"`
	KeyType         protocol.KeyType           `cbor:"7,keyasint"`
	DeviceKeyHandle uint32                     `cbor:"8,keyasint"`
	HMACKeyHandle   uint32                     `cbor:"9,keyasint"`
}
