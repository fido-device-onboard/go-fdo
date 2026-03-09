//go:build hardware_tpm
// +build hardware_tpm

// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package tpm_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/google/go-tpm/tpm2/transport/linuxtpm"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/tpm"
)

// openHardwareTPM tries to open a TPM device, first the resource manager then direct access
func openHardwareTPM(t *testing.T) (tpm.TPM, func()) {
	// Try TPM Resource Manager first (recommended)
	tpmDevice, err := linuxtpm.Open("/dev/tpmrm0")
	if err == nil {
		t.Log("Using hardware TPM Resource Manager: /dev/tpmrm0")
		return tpmDevice, func() { tpmDevice.Close() }
	}

	// Fallback to direct TPM access
	tpmDevice, err = linuxtpm.Open("/dev/tpm0")
	if err == nil {
		t.Log("Using hardware TPM (direct access): /dev/tpm0")
		return tpmDevice, func() { tpmDevice.Close() }
	}

	t.Skipf("No TPM hardware available: /dev/tpmrm0: %v, /dev/tpm0: %v", err, err)
	panic("unreachable")
}

func TestTPMDeviceHardware(t *testing.T) {
	tpmDevice, closeFn := openHardwareTPM(t)
	defer closeFn()

	t.Log("Running hardware TPM test with P256 only")

	// Test basic TPM functionality first
	hmacSha256, err := tpm.NewHmac(tpmDevice, crypto.SHA256)
	if err != nil {
		t.Fatalf("Failed to create HMAC SHA256: %v", err)
	}
	defer hmacSha256.Close()

	hmacSha384, err := tpm.NewHmac(tpmDevice, crypto.SHA384)
	if err != nil {
		t.Fatalf("Failed to create HMAC SHA384: %v", err)
	}
	defer hmacSha384.Close()

	key, err := tpm.GenerateECKey(tpmDevice, elliptic.P256())
	if err != nil {
		t.Fatalf("Failed to generate P256 key: %v", err)
	}
	defer key.Close()

	t.Log("✅ TPM basic functionality test passed")
	t.Log("✅ P256 key generation works")
	t.Log("✅ HMAC SHA256/SHA384 work")

	// Test that we can create a device credential with the TPM key
	guid := protocol.GUID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	deviceCred := tpm.DeviceCredential{
		DeviceCredential: fdo.DeviceCredential{
			Version:    1,
			DeviceInfo: "test-device",
			GUID:       guid,
			PublicKeyHash: protocol.Hash{
				Algorithm: protocol.Sha256Hash,
				Value:     []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
			},
		},
		DeviceKey:       tpm.FdoDeviceKey,
		DeviceKeyHandle: 0x81000001, // Example handle
	}

	t.Logf("✅ Created device credential: %s", deviceCred.String())

	// Test signing with the TPM key
	hash := crypto.SHA256.New()
	hash.Write([]byte("test message"))
	digest := hash.Sum(nil)

	signature, err := key.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		t.Fatalf("Failed to sign with TPM key: %v", err)
	}

	t.Logf("✅ Successfully signed data with TPM key (signature length: %d)", len(signature))

	// Verify the signature
	if !ecdsa.VerifyASN1(key.Public().(*ecdsa.PublicKey), digest, signature) {
		t.Fatal("Signature verification failed")
	}

	t.Log("✅ Signature verification passed")
	t.Log("🎉 Hardware TPM test completed successfully!")
}

var p384Supported bool
