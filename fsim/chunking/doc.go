// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

/*
Package chunking provides generic chunking support for FDO Service Info Modules (FSIMs).

This package implements the common pattern defined in chunking-strategy.md for transmitting
large payloads inside FDO ServiceInfo Modules. The goal is to keep transport rules consistent
across all modules so that devices and owners can share code and expectations.

# Message Pattern

The chunking strategy follows a begin/data/end/result flow:

  - *-begin: Announces the start of a transfer and provides metadata
  - *-data-<n>: Payload chunks (0-based index embedded in key name)
  - *-end: Signals completion and may carry final metadata
  - *-result: Receiver acknowledges completion (optional)

# Device-Side Usage

Create a ChunkReceiver with callbacks for FSIM-specific handling:

	receiver := &chunking.ChunkReceiver{
		PayloadName: "cert",
		OnBegin: func(begin chunking.BeginMessage) error {
			// Extract FSIM-specific metadata from negative keys
			networkID := begin.FSIMFields[-1].(string)
			return prepareForCert(networkID)
		},
		OnChunk: func(data []byte) error {
			return accumulateCertData(data)
		},
		OnEnd: func(end chunking.EndMessage) error {
			return installCertificate(receiver.GetBuffer())
		},
	}

	// In your FSIM's Receive method
	if err := receiver.HandleMessage(messageName, messageBody); err != nil {
		return err
	}

	// Send result after end
	if strings.HasSuffix(messageName, "-end") {
		return receiver.SendResult(respond, 0, "success")
	}

# Owner-Side Usage

Create a ChunkSender and manage the send flow:

	sender := chunking.NewChunkSender("cert", certData)
	sender.BeginFields.HashAlg = "sha256"
	sender.BeginFields.FSIMFields[-1] = "network-001"  // FSIM-specific

	// In ProduceInfo, send begin/chunks/end sequentially
	if sender.GetBytesSent() == 0 {
		return sender.SendBegin(producer)
	}
	if !sender.IsCompleted() {
		done, err := sender.SendNextChunk(producer)
		if !done {
			return false, false, err  // More chunks
		}
		return sender.SendEnd(producer)
	}

# FSIM-Specific Metadata

FSIMs define their own metadata using negative integer keys to avoid conflicts
with generic fields (keys 0-127):

	// WiFi FSIM
	sender.BeginFields.FSIMFields[-1] = "network-002"      // network_id
	sender.BeginFields.FSIMFields[-2] = "Enterprise-WiFi"  // ssid
	sender.BeginFields.FSIMFields[-3] = 0                  // csr_type

	// Payload FSIM
	sender.BeginFields.FSIMFields[-1] = "application/x-sh"  // mime_type
	sender.BeginFields.FSIMFields[-2] = "setup.sh"          // name

# Error Handling

Protocol-level errors (hash/length mismatches) abort the TO2 exchange.
FSIM-level errors are reported via the result message:

	receiver.SendResult(respond, 2, "Certificate validation failed")

Status codes: 0=success, 1=warning, 2=error, ≥3=FSIM-defined

# Hash Verification

The package supports SHA-256, SHA-384, and SHA-512:

	hash, err := chunking.ComputeHash("sha256", data)
	err = chunking.VerifyHash("sha256", data, expectedHash)

Hashes are automatically computed when AutoComputeHash is enabled (default).
*/
package chunking
