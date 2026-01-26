// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package chunking_test

import (
	"bytes"
	"fmt"
	"io"
	"log"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/fsim/chunking"
)

// Example demonstrates how to use ChunkReceiver on the device side
func Example_receiver() {
	// Create a receiver for WiFi certificates
	var installedCert []byte
	var receiver *chunking.ChunkReceiver
	receiver = &chunking.ChunkReceiver{
		PayloadName: "cert",
		OnBegin: func(begin chunking.BeginMessage) error {
			networkID := begin.FSIMFields[-1].(string)
			log.Printf("Receiving certificate for network: %s", networkID)
			return nil
		},
		OnChunk: func(data []byte) error {
			log.Printf("Received chunk: %d bytes", len(data))
			return nil
		},
		OnEnd: func(end chunking.EndMessage) error {
			installedCert = receiver.GetBuffer()
			log.Printf("Certificate received: %d bytes", len(installedCert))
			return nil
		},
	}

	// Simulate receiving begin message
	begin := chunking.BeginMessage{
		TotalSize: 100,
		HashAlg:   "sha256",
		FSIMFields: map[int]any{
			-1: "network-001",
			-2: "Enterprise-WiFi",
		},
	}
	beginData, _ := begin.MarshalCBOR()
	receiver.HandleMessage("cert-begin", bytes.NewReader(beginData))

	// Simulate receiving data chunks
	chunk1 := []byte("certificate data part 1...")
	chunk1Data, _ := cbor.Marshal(chunk1)
	receiver.HandleMessage("cert-data-0", bytes.NewReader(chunk1Data))

	chunk2 := []byte("certificate data part 2...")
	chunk2Data, _ := cbor.Marshal(chunk2)
	receiver.HandleMessage("cert-data-1", bytes.NewReader(chunk2Data))

	// Simulate receiving end message
	fullData := append(chunk1, chunk2...)
	hash, _ := chunking.ComputeHash("sha256", fullData)
	end := chunking.EndMessage{
		Status:    0,
		HashValue: hash,
	}
	endData, _ := end.MarshalCBOR()
	receiver.HandleMessage("cert-end", bytes.NewReader(endData))

	fmt.Printf("Certificate installed: %d bytes\n", len(installedCert))
	// Output: Certificate installed: 52 bytes
}

// Example demonstrates how to use ChunkSender on the owner side
func Example_sender() {
	// Create certificate data to send
	certData := []byte("This is a certificate that will be chunked and sent to the device")

	// Create a sender
	sender := chunking.NewChunkSender("cert", certData)
	sender.ChunkSize = 20 // Small chunks for demo
	sender.BeginFields.HashAlg = "sha256"
	sender.BeginFields.FSIMFields[-1] = "network-001"
	sender.BeginFields.FSIMFields[-2] = "Enterprise-WiFi"

	// Mock producer to capture messages
	producer := &mockProducer{messages: make(map[string][]byte)}

	// Send begin
	sender.SendBegin(producer)
	fmt.Println("Sent begin message")

	// Send all chunks
	chunkCount := 0
	for {
		done, _ := sender.SendNextChunk(producer)
		if done {
			break
		}
		chunkCount++
		fmt.Printf("Sent chunk %d\n", chunkCount-1)
	}

	// Send end
	sender.SendEnd(producer)
	fmt.Println("Sent end message")

	fmt.Printf("Total messages sent: %d\n", len(producer.messages))
	fmt.Printf("Progress: %.0f%%\n", sender.GetProgress())

	// Output:
	// Sent begin message
	// Sent chunk 0
	// Sent chunk 1
	// Sent chunk 2
	// Sent chunk 3
	// Sent end message
	// Total messages sent: 6
	// Progress: 100%
}

// Example demonstrates FSIM-specific metadata for WiFi CSR
func Example_wifiCSR() {
	// Device sends CSR to owner
	csrData := []byte("-----BEGIN CERTIFICATE REQUEST-----\n...")

	sender := chunking.NewChunkSender("csr", csrData)
	sender.BeginFields.TotalSize = uint64(len(csrData))
	sender.BeginFields.HashAlg = "sha256"

	// WiFi-specific metadata (negative keys)
	sender.BeginFields.FSIMFields[-1] = "network-002"     // network_id
	sender.BeginFields.FSIMFields[-2] = "Enterprise-WiFi" // ssid
	sender.BeginFields.FSIMFields[-3] = 0                 // csr_type (eap-tls)

	fmt.Printf("CSR payload: %d bytes\n", len(csrData))
	fmt.Printf("Network ID: %s\n", sender.BeginFields.FSIMFields[-1])
	fmt.Printf("SSID: %s\n", sender.BeginFields.FSIMFields[-2])

	// Output:
	// CSR payload: 44 bytes
	// Network ID: network-002
	// SSID: Enterprise-WiFi
}

// Example demonstrates FSIM-specific metadata for Payload FSIM
func Example_payloadFSIM() {
	// Owner sends script to device
	scriptData := []byte("#!/bin/bash\necho 'Setup complete'\n")

	sender := chunking.NewChunkSender("payload", scriptData)
	sender.BeginFields.TotalSize = uint64(len(scriptData))
	sender.BeginFields.HashAlg = "sha256"

	// Payload-specific metadata (negative keys)
	sender.BeginFields.FSIMFields[-1] = "application/x-sh" // mime_type
	sender.BeginFields.FSIMFields[-2] = "setup.sh"         // name
	sender.BeginFields.FSIMFields[-3] = map[string]any{    // metadata
		"version":     "1.0",
		"description": "Initial setup script",
	}

	fmt.Printf("Payload: %d bytes\n", len(scriptData))
	fmt.Printf("MIME type: %s\n", sender.BeginFields.FSIMFields[-1])
	fmt.Printf("Name: %s\n", sender.BeginFields.FSIMFields[-2])

	// Output:
	// Payload: 37 bytes
	// MIME type: application/x-sh
	// Name: setup.sh
}

// Example demonstrates hash computation and verification
func Example_hashVerification() {
	data := []byte("Important data that needs integrity verification")

	// Compute hash
	hash, err := chunking.ComputeHash("sha256", data)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Hash computed: %d bytes\n", len(hash))

	// Verify hash
	err = chunking.VerifyHash("sha256", data, hash)
	if err != nil {
		fmt.Println("Hash verification failed")
	} else {
		fmt.Println("Hash verification succeeded")
	}

	// Verify with wrong hash
	wrongHash := make([]byte, len(hash))
	err = chunking.VerifyHash("sha256", data, wrongHash)
	if err != nil {
		fmt.Println("Wrong hash detected")
	}

	// Output:
	// Hash computed: 32 bytes
	// Hash verification succeeded
	// Wrong hash detected
}

// Mock producer for examples
type mockProducer struct {
	messages map[string][]byte
}

func (m *mockProducer) WriteChunk(key string, data []byte) error {
	m.messages[key] = data
	return nil
}

func (m *mockProducer) Write(moduleName, messageName string, messageBody io.Reader) error {
	return nil
}
