# Generic Chunking Pattern for FSIMs

## Overview

This document describes the generic chunking pattern that FSIMs can use to support both **unified** (buffered) and **chunked** (streaming) payload handling. This pattern abstracts away the complexity of chunking from application developers while still supporting memory-constrained scenarios.

## Problem Statement

FSIMs that transfer large data (payloads, certificates, etc.) need to handle chunking transparently. However, applications have different requirements:

- **Most applications**: Want to receive complete data at once (like `SysConfig` does with parameters)
- **Memory-constrained devices**: Need to process chunks individually to avoid buffering large payloads

Previously, applications had to implement chunking logic themselves. This pattern provides a generic solution.

## Solution: Dual-Mode Handlers

Each FSIM that uses this pattern provides two handler interfaces:

### 1. UnifiedPayloadHandler (Recommended)

For applications that want the framework to handle chunking transparently:

```go
type UnifiedPayloadHandler interface {
    HandlePayload(ctx context.Context, mimeType, name string, size uint64, 
                  metadata map[string]any, payload []byte) (statusCode int, message string, err error)
}
```

**Characteristics:**

- Framework buffers all chunks automatically
- Application receives complete payload at once
- Simple to implement (similar to `SysConfig`)
- Suitable for payloads up to ~100MB on typical systems

**Example:**

```go
type MyPayloadHandler struct{}

func (h *MyPayloadHandler) HandlePayload(ctx context.Context, mimeType, name string, 
                                        size uint64, metadata map[string]any, 
                                        payload []byte) (int, string, error) {
    // Just process the complete payload
    if mimeType == "application/x-shell-script" {
        return executeScript(payload)
    }
    return 0, "OK", nil
}

// Usage:
fsim := &fsim.Payload{
    UnifiedHandler: &MyPayloadHandler{},
}
```

### 2. ChunkedPayloadHandler (For Memory-Constrained Scenarios)

For applications that need to process chunks individually:

```go
type ChunkedPayloadHandler interface {
    SupportsMimeType(mimeType string) bool
    BeginPayload(mimeType, name string, size uint64, metadata map[string]any) error
    ReceiveChunk(data []byte) error
    EndPayload() (statusCode int, message string, err error)
    CancelPayload() error
}
```

**Characteristics:**

- Framework calls handler for each chunk
- Application processes chunks as they arrive
- Suitable for streaming to disk or network
- Suitable for memory-limited systems

**Example:**

```go
type StreamingPayloadHandler struct {
    file *os.File
}

func (h *StreamingPayloadHandler) SupportsMimeType(mimeType string) bool {
    return mimeType == "application/octet-stream"
}

func (h *StreamingPayloadHandler) BeginPayload(mimeType, name string, 
                                              size uint64, metadata map[string]any) error {
    f, err := os.Create(name)
    h.file = f
    return err
}

func (h *StreamingPayloadHandler) ReceiveChunk(data []byte) error {
    _, err := h.file.Write(data)
    return err
}

func (h *StreamingPayloadHandler) EndPayload() (int, string, error) {
    h.file.Close()
    return 0, "OK", nil
}

func (h *StreamingPayloadHandler) CancelPayload() error {
    return h.file.Close()
}

// Usage:
fsim := &fsim.Payload{
    ChunkedHandler: &StreamingPayloadHandler{},
}
```

## Implementation Pattern

### FSIM Structure

```go
type Payload struct {
    // Option 1: Simple unified handler (framework buffers chunks)
    UnifiedHandler UnifiedPayloadHandler
    
    // Option 2: Chunked handler (app handles chunks individually)
    ChunkedHandler ChunkedPayloadHandler
    
    // Internal state
    receiver     *chunking.ChunkReceiver
    buffer       *bytes.Buffer
    begin        chunking.BeginMessage
    resultStatus int
    resultMsg    string
}
```

### Initialization

```go
// Initialize receiver on first message
if p.receiver == nil {
    p.receiver = &chunking.ChunkReceiver{
        PayloadName: "payload",
    }
    
    if p.UnifiedHandler != nil {
        // Unified mode: buffer everything
        p.buffer = &bytes.Buffer{}
        p.receiver.OnBegin = p.onBeginUnified
        p.receiver.OnChunk = p.onChunkUnified
        p.receiver.OnEnd = p.onEndUnified(ctx)
    } else {
        // Chunked mode: delegate to handler
        p.receiver.OnBegin = p.onBeginChunked
        p.receiver.OnChunk = p.onChunkChunked
        p.receiver.OnEnd = p.onEndChunked
    }
}
```

### Callback Implementation

**Unified Mode:**

```go
func (p *Payload) onBeginUnified(begin chunking.BeginMessage) error {
    p.begin = begin
    return nil
}

func (p *Payload) onChunkUnified(data []byte) error {
    p.buffer.Write(data)
    return nil
}

func (p *Payload) onEndUnified(ctx context.Context) func(chunking.EndMessage) error {
    return func(end chunking.EndMessage) error {
        // Extract metadata from begin message
        mimeType := p.begin.FSIMFields[-1].(string)
        name := p.begin.FSIMFields[-2].(string)
        
        // Call unified handler with complete payload
        statusCode, message, err := p.UnifiedHandler.HandlePayload(
            ctx, mimeType, name, p.begin.TotalSize, nil, p.buffer.Bytes())
        
        p.resultStatus = statusCode
        p.resultMsg = message
        return err
    }
}
```

**Chunked Mode:**

```go
func (p *Payload) onBeginChunked(begin chunking.BeginMessage) error {
    mimeType := begin.FSIMFields[-1].(string)
    name := begin.FSIMFields[-2].(string)
    
    if !p.ChunkedHandler.SupportsMimeType(mimeType) {
        return fmt.Errorf("MIME type not supported")
    }
    
    return p.ChunkedHandler.BeginPayload(mimeType, name, begin.TotalSize, nil)
}

func (p *Payload) onChunkChunked(data []byte) error {
    return p.ChunkedHandler.ReceiveChunk(data)
}

func (p *Payload) onEndChunked(end chunking.EndMessage) error {
    statusCode, message, err := p.ChunkedHandler.EndPayload()
    p.resultStatus = statusCode
    p.resultMsg = message
    return err
}
```

## Applying This Pattern to Other FSIMs

### WiFi FSIM

The WiFi FSIM could use this pattern for certificate data:

```go
type UnifiedCertificateHandler interface {
    HandleCertificate(ctx context.Context, networkID, ssid string, 
                     certData []byte) (statusCode int, message string, err error)
}

type WiFi struct {
    UnifiedCertHandler UnifiedCertificateHandler
    ChunkedCertHandler ChunkedCertificateHandler
    // ... rest of fields
}
```

### CSR FSIM

The CSR FSIM could use this for CSR data:

```go
type UnifiedCSRHandler interface {
    HandleCSR(ctx context.Context, networkID string, 
             csrData []byte) (statusCode int, message string, err error)
}
```

## Benefits

| Aspect | Benefit |
|--------|---------|
| **Simplicity** | Applications don't need to understand chunking |
| **Flexibility** | Support both buffered and streaming scenarios |
| **Reusability** | Pattern can be applied to any chunked FSIM |
| **Memory Efficiency** | Chunked mode for resource-constrained devices |
| **Backward Compatibility** | Existing chunked handlers still work |
| **Generic** | Chunking logic stays in library, not duplicated in FSIMs |

## Testing

Test both modes:

```go
// Test unified mode
fsim := &fsim.Payload{
    UnifiedHandler: &testUnifiedHandler{},
}

// Test chunked mode
fsim := &fsim.Payload{
    ChunkedHandler: &testChunkedHandler{},
}

// Both should produce identical results
```

## Conclusion

This pattern provides a clean abstraction for handling chunked data in FSIMs. Applications can choose the mode that best fits their needs:

- **Unified mode** for simplicity and most use cases
- **Chunked mode** for streaming and memory-constrained scenarios

The framework handles all the complexity of chunking, buffering, and reassembly transparently.
