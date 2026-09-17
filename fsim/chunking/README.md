# FSIM Chunking Package

This package provides generic, reusable chunking support for FDO Service Info Modules (FSIMs) following the pattern defined in [chunking-strategy.md](https://github.com/bkgoodman/fdo-sim/blob/main/fsim-repository/chunking-strategy.md), maintained in the `fdo-sim` repository. See [SPECIFICATIONS.md](../../SPECIFICATIONS.md).

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

Note that "device-side" and "owner-side" describe the *typical* deployment, not
a restriction. Both types are direction-agnostic; see
[Reverse-Direction Transfers](#reverse-direction-transfers).

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

## Reverse-Direction Transfers

The chunking rules are defined in terms of *sender* and *receiver*, not owner
and device, so either party may send a chunked payload. The primary use is
**diagnostic logs**: the device uploads handler output to the owner after
applying a payload (see `chunking-strategy.md` "Diagnostic Payloads").

A device sends with the `*ToWriter` variants, which take the device module's
`respond func(string) io.Writer` in place of a `Producer`:

```go
sender := chunking.NewChunkSender("payload-log", logBytes)
sender.BeginFields.HashAlg = "sha256"
sender.BeginFields.RequireAck = true
sender.BeginFields.Metadata = map[string]any{
    "content_type": "text/plain",
    "source":       "installer",
}
// Size chunks to the negotiated MTU.
if mtu, ok := ctx.Value(serviceinfo.MTUKey{}).(uint16); ok {
    sender.ChunkSize = int(mtu) - 100
}

if err := sender.SendBeginToWriter(respond); err != nil { /* ... */ }
// ...after the peer's *-log-ack accepts:
for {
    done, err := sender.SendNextChunkToWriter(respond)
    if err != nil { /* ... */ }
    if done { break }
}
err := sender.SendEndToWriter(respond)
```

The owner receives with an ordinary `ChunkReceiver`, then replies through
`ProduceInfo` rather than a `respond` writer.

### Three Traps

**Drive it from `Receive`, not `Yield`.** `Yield` is never called on the FDO 2.0
client path (`processOwnerServiceInfo20`), so a `Yield`-based implementation
compiles, passes 1.0.1 tests, and silently does nothing under
`-fdo-version 200`.

**`IsAckPending()` is cleared only by `SendAck`.** An owner replying through
`ProduceInfo` cannot call `SendAck` (it has no `respond` writer), so the flag
stays set and every subsequent chunk will re-queue a duplicate ack unless the
check is gated to the begin message:

```go
isBegin := strings.HasSuffix(messageName, "-begin")
if isBegin && receiver.IsAckPending() {
    // capture the accept/reject decision for ProduceInfo to send
}
```

**Don't complete the module before the peer's `*-result` arrives.**
`ServiceInfoProcessor.ProcessServiceInfo` discards device KVs whose module name
does not match the current owner module cursor — they are dropped, not queued,
and (until recently) without any log line. An owner module that returns
`moduleDone = true` right after `*-end` will therefore lose the device's
`*-result`, and any diagnostic log that precedes it.

`PayloadOwner` avoids this by parking in `stateWaitingResult` and returning
`(false, false, nil)` until `payload-result` arrives. Do the same in any FSIM
that expects a reply. See `chunking-strategy.md` "Completion Ordering".

### Worked Example: `fdo.payload` Diagnostic Logs

`fsim.Payload` / `fsim.PayloadOwner` implement this pattern. Device side — set
`LogProvider`; returning `nil` suppresses the transfer. `MaxLogSize` caps the
upload (default 64 KiB) and sets the `truncated` flag.

```go
type LogProvider interface {
    PayloadLog(ctx context.Context, mimeType, name string, statusCode int) (*PayloadLog, error)
}

type PayloadLog struct {
    Data        []byte
    ContentType string // defaults to "text/plain"
    Truncated   bool
    Source      string // e.g. "installer", "stderr"
}

device := &fsim.Payload{
    UnifiedHandler: myHandler,
    LogProvider:    myLogProvider,
    MaxLogSize:     64 * 1024,
}
```

Owner side — set `LogHandler`. If nil, every offered log is declined with
reason 5. `GetLastLog()` returns the most recent upload.

```go
type PayloadLogHandler interface {
    AcceptLog(mimeType, name string, size uint64, contentType string) (accepted bool, reasonCode int, message string)
    HandleLog(ctx context.Context, mimeType, name string, log *PayloadLogInfo) error
}

owner := &fsim.PayloadOwner{LogHandler: myCollector}
```

A `HandleLog` error is logged but never fails the session — diagnostics are
supplementary by design. Exercise it end-to-end with
`./test_examples.sh payload-log`, or via the CLI:

```bash
go run ./cmd server -payload-file config.json -payload-log-dir ./device-logs
go run ./cmd client -payload-send-log
```

### Ack Reason Codes

| Constant | Value | Meaning |
| -------- | ----- | ------- |
| `AckReasonUnsupportedType` | 1 | MIME type or format not supported |
| `AckReasonSizeExceeded` | 2 | Payload too large |
| `AckReasonNotApplicable` | 3 | Not applicable to current state |
| `AckReasonPolicyViolation` | 4 | Rejected by policy |
| `AckReasonDiagnosticsNotRequested` | 5 | Peer does not want the diagnostic log |

## Future Enhancements

Potential improvements (not yet implemented):

- Compression support
- Chunk retransmission on error
- Progress callbacks for UI updates
- Streaming to disk for very large payloads
- Multi-part payload support
