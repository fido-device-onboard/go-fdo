package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/blob"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"os"
	"testing"
)

func TestSaveCredential(t *testing.T) {

	// Test Setup
	publicKeyHashValue, _ := hex.DecodeString("1370f27bcfbd9c39c88c0cd81b94b19d2ccb833acea86625ad8fed212d3d2dcbce2c556b070a9507144b61e7f482d9af")
	hmacSecret, _ := hex.DecodeString("508a689131a5739359baab1f6dc5e53cd03aa9101205f689a96c6a8de78a1b21")
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	guid := protocol.GUID{12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27}
	deviceCred := fdo.DeviceCredential{
		Version:    101,
		DeviceInfo: "go-fgo-client",
		GUID:       guid,
		PublicKeyHash: protocol.Hash{
			Algorithm: protocol.Sha384Hash,
			Value:     publicKeyHashValue,
		},
		RvInfo: make([][]protocol.RvInstruction, 0),
	}

	// Create the DeviceCredential object
	inputDc := blob.DeviceCredential{
		Active:           true,
		DeviceCredential: deviceCred,
		HmacSecret:       hmacSecret,
		PrivateKey:       blob.Pkcs8Key{Signer: key},
	}

	blobPath = "./cred.bin"

	//Execute Test
	if err := saveCred(inputDc); err != nil {
		t.Fatalf("SaveCredential failed: %v", err)
	}

	var dcWrittenToFile blob.DeviceCredential
	if err := readCredFile(&dcWrittenToFile); err != nil {
		t.Fatalf("readCredFile failed: %v", err)
	}

	//cleanup
	if _, err := os.Stat(blobPath); err == nil {
		// File exists, so delete it
		err := os.Remove(blobPath)
		if err != nil {
			fmt.Printf("Error deleting file: %v\n", err)
		}
	}

	//Validate Result
	if dcWrittenToFile.DeviceCredential.DeviceInfo != inputDc.DeviceCredential.DeviceInfo {
		t.Errorf("Unexpected DeviceInfo. Expected DeviceInfo: %s, Received DeviceInfo:%s\n",
			inputDc.DeviceCredential.DeviceInfo, dcWrittenToFile.DeviceCredential.DeviceInfo)
	}

	if dcWrittenToFile.DeviceCredential.GUID != inputDc.DeviceCredential.GUID {
		t.Errorf("Unexpected GUID. Expected GUID: %d, Received GUID:%d\n",
			inputDc.DeviceCredential.GUID, dcWrittenToFile.DeviceCredential.GUID)
	}
}
