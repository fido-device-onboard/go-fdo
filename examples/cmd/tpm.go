// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

//go:build !tinygo

package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/tpm"
)

const tpmSimulatorPath = "simulator"

func tpmOpen(tpmPath string) (tpm.Closer, error) {
	if tpmPath == "" {
		// No explicit path — use build-tag-selected default
		return tpm.DefaultOpen()
	}
	if tpmPath == tpmSimulatorPath {
		sim, err := simulator.GetWithFixedSeedInsecure(8086)
		if err != nil {
			return nil, err
		}
		return transport.FromReadWriteCloser(sim), nil
	}
	// Auto-detect Unix socket (swtpm) vs character device (hardware TPM)
	fi, err := os.Stat(tpmPath)
	if err != nil {
		return nil, fmt.Errorf("opening TPM at %s: %w", tpmPath, err)
	}
	if fi.Mode()&os.ModeSocket != 0 {
		return linuxudstpm.Open(tpmPath)
	}
	return linuxtpm.Open(tpmPath)
}

// tpmClearCredentials removes all FDO NV indices and persistent handles from the TPM.
// This works equally on hardware TPM and simulator.
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

// tpmShowCredentials reads and displays all FDO credentials stored in TPM NV indices.
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
	fmt.Printf("  DCActive (0x%08X)    %v", tpm.DCActiveIndex, info.Active)
	if info.DCActiveSize > 0 {
		fmt.Printf("  [%d bytes]", info.DCActiveSize)
	} else {
		fmt.Print("  [not defined]")
	}
	fmt.Println()

	if info.DCTPMSize > 0 {
		fmt.Printf("  DCTPM (0x%08X)      [%d bytes]\n", tpm.DCTPMIndex, info.DCTPMSize)
		fmt.Printf("    GUID              %x\n", info.GUID)
		fmt.Printf("    DeviceInfo        %q\n", info.DeviceInfo)
	} else {
		fmt.Printf("  DCTPM (0x%08X)      [not defined]\n", tpm.DCTPMIndex)
	}

	if info.HasDCOV {
		fmt.Printf("  DCOV (0x%08X)       [%d bytes]\n", tpm.DCOVIndex, info.DCOVSize)
		if len(info.DCOVData) > 0 {
			var dcov dcovDisplay
			if err := cbor.Unmarshal(info.DCOVData, &dcov); err != nil {
				fmt.Printf("    (decode error: %v)\n", err)
			} else {
				fmt.Printf("    Version           %d\n", dcov.Version)
				fmt.Printf("    KeyType           %s\n", dcov.KeyType)
				if dcov.HMACHandle != 0 {
					fmt.Printf("    HMACHandle        0x%08X\n", dcov.HMACHandle)
				}
				fmt.Printf("    PublicKeyHash     alg=%d value=%s\n", dcov.PublicKeyHash.Algorithm, hex.EncodeToString(dcov.PublicKeyHash.Value))
				if len(dcov.RvInfo) == 0 {
					fmt.Println("    RvInfo            (none)")
				} else {
					directives := protocol.ParseDeviceRvInfo(dcov.RvInfo)
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
					}
				}
			}
		}
	} else {
		fmt.Printf("  DCOV (0x%08X)       [not defined]\n", tpm.DCOVIndex)
	}

	if info.HMACUSSize > 0 {
		fmt.Printf("  HMAC_US (0x%08X)    [%d bytes]\n", tpm.HMACUSIndex, info.HMACUSSize)
	} else {
		fmt.Printf("  HMAC_US (0x%08X)    [not defined]\n", tpm.HMACUSIndex)
	}

	if info.DeviceKeyUSSize > 0 {
		fmt.Printf("  DeviceKey_US (0x%08X) [%d bytes]\n", tpm.DeviceKeyUSIndex, info.DeviceKeyUSSize)
	} else {
		fmt.Printf("  DeviceKey_US (0x%08X) [not defined]\n", tpm.DeviceKeyUSIndex)
	}

	if info.HasCert {
		fmt.Printf("  FDO_Cert (0x%08X)   [%d bytes]\n", tpm.FDOCertIndex, info.FDOCertSize)
	} else {
		fmt.Printf("  FDO_Cert (0x%08X)   [not defined]\n", tpm.FDOCertIndex)
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

// dcovDisplay mirrors the CBOR structure stored in the DCOV NV index.
// Defined here (rather than importing from cred) because the cred package
// type is unexported and requires a build tag.
type dcovDisplay struct {
	Version       uint16                     `cbor:"0,keyasint"`
	RvInfo        [][]protocol.RvInstruction `cbor:"1,keyasint"`
	PublicKeyHash protocol.Hash              `cbor:"2,keyasint"`
	KeyType       protocol.KeyType           `cbor:"3,keyasint"`
	HMACHandle    uint32                     `cbor:"4,keyasint,omitempty"`
}
