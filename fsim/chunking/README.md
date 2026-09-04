# FSIM Chunking Package

This package provides generic, reusable chunking support for FDO Service Info Modules (FSIMs) following the pattern defined in [chunking-strategy.md](../../chunking-strategy.md).

## Overview

The chunking package implements the common begin/data/end/result message flow that allows FSIMs to transmit large payloads without being constrained by MTU limits. This keeps transport rules consistent across all modules so that devices and owners can share code and expectations.

## Key Components

### Data Structures

- **`BeginMessage`**: Represents the `*-begin` message with generic fields (keys 0-127) and FSIM-specific fields (negative keys)
- **`EndMessage`**: Represents the `*-end` message with status, hash, and optional metadata
- **`ResultMessage`**: Represents the `*-result` acknowledgment sent by receivers

### Device-Side (Receiver)

- **`ChunkReceiver`**: Handles receiving chunked payloads with callbacks for FSIM-specific processing

### Owner-Side (Sender)

- **`ChunkSender`**: Handles sending chunked payloads with automatic hash computation and progress tracking

### Utilities

- **Hash functions**: `ComputeHash()` and `VerifyHash()` for SHA-256, SHA-384, and SHA-512

## Usage Examples

### Device-Side: Receiving a Chunked Payload

```go
import "github.com/fido-device-onboard/go-fdo/fsim/chunking"

// Create a receiver for the "cert" payload
receiver := &chunking.ChunkReceiver{
    PayloadName: "cert",
    
    OnBegin: func(begin chunking.BeginMessage) error {
        // Extract FSIM-specific metadata
        networkID := begin.FSIMFields[-1].(string)
        log.Printf("Receiving certificate for network: %s", networkID)
        
        // Prepare to receive the payload
        return prepareForCertificate(networkID, begin.TotalSize)
    },
    
    OnChunk: func(data []byte) error {
        // Process each chunk as it arrives
        return accumulateCertData(data)
    },
    
    OnEnd: func(end chunking.EndMessage) error {
        // Finalize and install the certificate
        certData := receiver.GetBuffer()
        return installCertificate(certData)
    },
}

// In your FSIM's Receive method:
func (f *WiFiFSIM) Receive(ctx context.Context, messageName string, 
                           messageBody io.Reader, respond func(string) io.Writer, 
                           yield func()) error {
    
    // Handle chunked messages
    if strings.HasPrefix(messageName, "cert-") {
        if err := receiver.HandleMessage(messageName, messageBody); err != nil {
            return err
        }
        
        // Send result after end message
        if strings.HasSuffix(messageName, "-end") {
            return receiver.SendResult(respond, 0, "Certificate installed")
        }
    }
    
    return nil
}
```

### Owner-Side: Sending a Chunked Payload

```go
import "github.com/fido-device-onboard/go-fdo/fsim/chunking"

// Create a sender for certificate data
certData := loadCertificateData()
sender := chunking.NewChunkSender("cert", certData)

// Configure metadata
sender.BeginFields.HashAlg = "sha256"
sender.BeginFields.FSIMFields[-1] = "network-001"  // network_id
sender.BeginFields.FSIMFields[-2] = "Enterprise-WiFi"  // ssid

// In your FSIM's ProduceInfo method:
func (f *WiFiOwner) ProduceInfo(ctx context.Context, 
                                producer *serviceinfo.Producer) (bool, bool, error) {
    
    // Send begin message
    if !sender.IsCompleted() && sender.GetBytesSent() == 0 {
        if err := sender.SendBegin(producer); err != nil {
            return false, false, err
        }
        return false, false, nil
    }
    
    // Send chunks
    if !sender.IsCompleted() {
        done, err := sender.SendNextChunk(producer)
        if err != nil {
            return false, false, err
        }
        if !done {
            return false, false, nil  // More chunks to send
        }
    }
    
    // Send end message
    if sender.GetBytesSent() == int64(len(certData)) && !sender.IsCompleted() {
        if err := sender.SendEnd(producer); err != nil {
            return false, false, err
        }
    }
    
    // Module done
    return false, true, nil
}

// Handle result message
func (f *WiFiOwner) HandleInfo(ctx context.Context, messageName string, 
                               messageBody io.Reader) error {
    if messageName == "cert-result" {
        result, err := sender.HandleResult(messageBody)
        if err != nil {
            return err
        }
        
        if result.StatusCode == 0 {
            log.Printf("Certificate installed: %s", result.Message)
        } else {
            log.Printf("Certificate failed: %s", result.Message)
        }
    }
    return nil
}
```

## FSIM-Specific Metadata

Each FSIM can define its own metadata fields using **negative integer keys** in the `BeginMessage` and `EndMessage` structures. This avoids conflicts with the generic fields (keys 0-127).

### Example: WiFi FSIM

```go
// WiFi CSR begin message
sender.BeginFields.FSIMFields[-1] = "network-002"      // network_id
sender.BeginFields.FSIMFields[-2] = "Enterprise-WiFi"  // ssid
sender.BeginFields.FSIMFields[-3] = 0                  // csr_type (eap-tls)
```

### Example: Payload FSIM

```go
// Payload begin message
sender.BeginFields.FSIMFields[-1] = "application/x-sh"  // mime_type
sender.BeginFields.FSIMFields[-2] = "setup.sh"          // name
sender.BeginFields.FSIMFields[-3] = map[string]any{     // metadata
    "version": "1.0",
    "description": "Initial setup script",
}
```

## Message Flow

The typical chunking flow follows this pattern:

```text
Owner                           Device
  |                               |
  | *-begin (metadata)            |
  |------------------------------>|
  |                               | Prepare to receive
  |                               |
  | *-data-0 (chunk 0)            |
  |------------------------------>|
  |                               | Accumulate chunk
  |                               |
  | *-data-1 (chunk 1)            |
  |------------------------------>|
  |                               | Accumulate chunk
  |                               |
  | ...                           |
  |                               |
  | *-end (hash, status)          |
  |------------------------------>|
  |                               | Verify & apply payload
  |                               |
  | *-result [status, message]    |
  |<------------------------------|
```

## Error Handling

### Protocol-Level Errors

Hash mismatches, length mismatches, and chunk corruption are **protocol-level errors** that MUST abort the TO2 ServiceInfo exchange:

```go
// These errors terminate the FSIM exchange
- Hash verification failed
- Size mismatch: expected X, received Y
- Chunk out of order
```

### FSIM-Level Errors

Application-level errors (e.g., "certificate rejected", "invalid configuration") are reported via the `*-result` message:

```go
receiver.SendResult(respond, 2, "Certificate validation failed")
```

Status codes:

- `0` = success
- `1` = warning
- `2` = error
- `≥3` = FSIM-defined values

## Integration with Existing FSIMs

To integrate this chunking package into a new FSIM:

1. **Import the package**: `import "github.com/fido-device-onboard/go-fdo/fsim/chunking"`

2. **Device side**: Create a `ChunkReceiver` with appropriate callbacks

3. **Owner side**: Create a `ChunkSender` and manage the send flow in `ProduceInfo`

4. **Define FSIM metadata**: Use negative keys in `BeginFields.FSIMFields` and `EndFields.FSIMFields`

5. **Reference chunking-strategy.md**: Your FSIM spec should reference the chunking strategy document instead of redefining chunk semantics

## Testing

The package includes comprehensive tests covering:

- Message marshaling/unmarshaling
- Hash computation and verification
- Receiver flow (begin/data/end)
- Sender flow with chunking
- Error conditions (out-of-order chunks, size mismatches, etc.)

Run tests with:

```bash
cd fsim/chunking
go test -v
```

## Design Rationale

### Why Generic?

Multiple FSIMs (wifi, payload, and future modules) need the same chunking behavior. This package:

- Eliminates code duplication
- Ensures consistency across FSIMs
- Simplifies testing and maintenance
- Makes it easy to add new chunked FSIMs

### Why Callbacks?

The callback-based design keeps the chunking logic generic while allowing FSIM-specific behavior:

- `OnBegin`: Validate metadata, prepare resources
- `OnChunk`: Process data incrementally (e.g., streaming to disk)
- `OnEnd`: Finalize and apply the payload

### Why Negative Keys?

Using negative integer keys for FSIM-specific metadata:

- Avoids conflicts with generic fields (keys 0-127)
- Maintains CBOR compactness
- Follows the pattern from chunking-strategy.md
- Allows future extensions without breaking changes

## Future Enhancements

Potential improvements (not yet implemented):

- Compression support
- Chunk retransmission on error
- Progress callbacks for UI updates
- Streaming to disk for very large payloads
- Multi-part payload support
