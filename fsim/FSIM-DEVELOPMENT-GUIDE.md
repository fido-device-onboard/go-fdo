# FSIM Development Guide: Common Issues and Patterns

This guide documents common hurdles, gotchas, and patterns discovered while implementing FSIMs (FDO Service Info Modules). It's not a complete tutorial, but rather a collection of issues that will save you debugging time.

## Table of Contents

1. [Active Message Handling](#active-message-handling)
2. [BlockPeer Flag Usage](#blockpeer-flag-usage)
3. [Chunking and ChunkWriter](#chunking-and-chunkwriter)
4. [Yield Method Patterns](#yield-method-patterns)
5. [Owner vs Device Module Differences](#owner-vs-device-module-differences)
6. [Common Pitfalls](#common-pitfalls)
7. [Debugging FSIM Failures: Systematic Approach](#debugging-fsim-failures-systematic-approach)

---

## Active Message Handling

### The Problem

The "active" message is used to activate/deactivate FSIMs, but its handling is **not symmetric** between owner and device.

### Owner Side (Sending Active)

```go
// ProduceInfo - send active message ONCE at the start
if !w.sentActive && len(w.data) > 0 {
    if err := producer.WriteChunk("active", []byte{0xf5}); err != nil { // 0xf5 is CBOR true
        return false, false, fmt.Errorf("failed to send active: %w", err)
    }
    w.sentActive = true
    return false, false, nil  // Don't block, just return
}
```

**Key Points:**

- Use a `sentActive` boolean flag to send it only once
- Send `0xf5` (CBOR true) as the value
- Return immediately after sending - don't try to do more work in the same call
- Only send if you have actual data to send

### Device Side (Receiving Active)

```go
// Receive - handle active message
if messageName == "active" {
    var active bool
    if err := cbor.NewDecoder(messageBody).Decode(&active); err != nil {
        return fmt.Errorf("invalid active message: %w", err)
    }
    w.Active = active
    
    // MUST respond with active state
    writer := respond("active")
    return cbor.NewEncoder(writer).Encode(w.Active)
}
```

**Key Points:**

- Device MUST respond to the active message
- Decode the boolean value from the message
- Respond with your active state (usually just echo it back)
- If you don't respond, you'll get: `"owner module did not read full body of message 'fdo.xxx:active'"`

### Owner Side (Receiving Active Response)

```go
// HandleInfo - read the active response
case "active":
    var deviceActive bool
    if err := cbor.NewDecoder(messageBody).Decode(&deviceActive); err != nil {
        return fmt.Errorf("error decoding active message: %w", err)
    }
    if !deviceActive {
        return fmt.Errorf("device module is not active")
    }
    return nil
```

**Key Points:**

- Owner MUST read the active response from device
- If you ignore it or don't read the body, the protocol will fail
- This is the most common cause of "TO2 failed" errors

### Pattern: Simple FSIMs (like SysConfig)

Some FSIMs don't handle the active message at all on the device side - they just ignore unknown messages. This works because:

- The owner sends active
- The device ignores it (returns nil for unknown messages)
- The owner doesn't expect a response

This pattern works for simple FSIMs that don't need bidirectional active confirmation.

---

## BlockPeer Flag Usage

### What BlockPeer Does

When `ProduceInfo` returns `blockPeer=true`, it tells the protocol:

- **Stop calling ProduceInfo** on the owner
- **Allow the device to send messages** via Yield
- **Wait for device messages** before continuing

### When to Use BlockPeer

**✅ Use BlockPeer When:**

- Waiting for device to send data (e.g., CSR, upload data)
- Device needs to respond before you can continue
- You need bidirectional communication

**❌ Don't Use BlockPeer When:**

- Just sending data to device (network-add, parameters, etc.)
- No response needed from device
- Sending multiple items in sequence

### Common BlockPeer Mistake

```go
// ❌ WRONG - This will hang forever
if network.AuthType == 3 {
    w.waitingForCSR = true
    return true, false, nil  // Blocks forever if device never sends CSR
}
```

**Problem:** If the device doesn't send CSR (or can't), the protocol hangs forever.

**Solution:** Only block if you're certain the device will respond:

```go
// ✅ CORRECT - Only block if we actually expect CSR
if network.AuthType == 3 && w.currentCertIndex < len(w.certificates) {
    w.waitingForCSR = true
    return true, false, nil  // Block and wait for CSR
}
```

### BlockPeer State Machine Pattern

```go
const (
    stateIdle
    stateSending
    stateWaitingForResponse  // Use blockPeer here
    stateProcessingResponse
)

func (w *Owner) ProduceInfo(...) (blockPeer, moduleDone bool, _ error) {
    switch w.state {
    case stateWaitingForResponse:
        return true, false, nil  // Block until device responds
    
    case stateProcessingResponse:
        // Process the response we received
        w.state = stateIdle
        return false, false, nil
    }
}
```

### Unblocking

To unblock, the owner's `HandleInfo` method receives the device's message:

```go
func (w *Owner) HandleInfo(ctx context.Context, messageName string, messageBody io.Reader) error {
    if messageName == "csr-end" {
        // Process CSR
        w.waitingForCSR = false  // Unblock
        w.state = stateProcessingResponse
    }
    return nil
}
```

---

## Chunking and ChunkWriter

### Owner Side: Sending Chunks

**Using ChunkSender (Recommended):**

```go
// Initialize sender
sender := chunking.NewChunkSender("cert", certData)
sender.BeginFields.FSIMFields = make(map[int]any)
sender.BeginFields.FSIMFields[-1] = networkID  // FSIM-specific metadata

// Send in ProduceInfo
if sender.GetBytesSent() == 0 {
    if err := sender.SendBegin(producer); err != nil {
        return false, false, err
    }
    return false, false, nil  // Return after begin
}

if !sender.IsCompleted() {
    done, err := sender.SendNextChunk(producer)
    if err != nil {
        return false, false, err
    }
    if done {
        if err := sender.SendEnd(producer); err != nil {
            return false, false, err
        }
        return true, false, nil  // Block and wait for result
    }
    return false, false, nil
}
```

**Key Points:**

- Send begin, chunks, and end in **separate ProduceInfo calls**
- Don't try to send everything in one call
- Return after each step to let the protocol flow
- Use `GetBytesSent()` to track progress

### Device Side: Receiving Chunks

**Using ChunkReceiver (Recommended):**

```go
// Initialize receiver on first message
if w.receiver == nil {
    w.receiver = &chunking.ChunkReceiver{
        PayloadName: "cert",
        OnBegin: func(begin chunking.BeginMessage) error {
            // Extract metadata
            networkID := begin.FSIMFields[-1].(string)
            return nil
        },
        OnChunk: func(data []byte) error {
            // Process chunk (or just accumulate)
            return nil
        },
        OnEnd: func(end chunking.EndMessage) error {
            // Get complete data
            completeData := w.receiver.GetBuffer()
            return w.processCertificate(completeData)
        },
    }
}

// Handle the message
if err := w.receiver.HandleMessage(messageName, messageBody); err != nil {
    w.receiver = nil
    return err
}

// Send result after end
if messageName == "cert-end" && !w.receiver.IsReceiving() {
    result := chunking.ResultMessage{
        StatusCode: 0,
        Message:    "Certificate installed",
    }
    resultData, _ := result.MarshalCBOR()
    writer := respond("cert-result")
    writer.Write(resultData)
    w.receiver = nil
}
```

**Key Points:**

- Initialize receiver on first message (begin)
- Use callbacks to process data
- Send result message after end
- Clean up receiver after completion

### Device Side: Sending Chunks (in Yield)

**Manual Chunking (for Yield):**

```go
func (w *Device) Yield(ctx context.Context, respond func(string) io.Writer, yield func()) error {
    if w.needToSendData {
        // Send begin
        writer := respond("data-begin")
        beginMsg := chunking.BeginMessage{
            TotalSize: uint64(len(w.data)),
            FSIMFields: make(map[int]any),
        }
        beginMsg.FSIMFields[-1] = w.metadata
        beginData, _ := beginMsg.MarshalCBOR()
        writer.Write(beginData)
        yield()  // IMPORTANT: Call yield() after each message
        
        // Send data
        writer = respond("data-data-0")
        writer.Write(w.data)
        yield()
        
        // Send end
        writer = respond("data-end")
        endMsg := chunking.EndMessage{}
        endData, _ := endMsg.MarshalCBOR()
        writer.Write(endData)
        yield()
        
        w.needToSendData = false
    }
    return nil
}
```

**Key Points:**

- Call `yield()` after **every message** you send
- Don't use ChunkSender in Yield (it expects a Producer interface)
- Manually construct begin/end messages
- Use CBOR encoding for messages

---

## Yield Method Patterns

### What Yield Does

`Yield` is called on the **device** to allow it to send messages to the owner. It's the device's turn to talk.

### When Yield is Called

- After device processes owner's messages
- When owner blocks (blockPeer=true)
- Periodically during TO2 protocol

### Yield Pattern: Send Data

```go
func (w *Device) Yield(ctx context.Context, respond func(string) io.Writer, yield func()) error {
    if w.hasDataToSend {
        writer := respond("my-message")
        writer.Write(w.data)
        yield()  // Signal that we sent something
        w.hasDataToSend = false
    }
    return nil  // Nothing to send
}
```

### Yield Pattern: Multi-Step Process

```go
func (w *Device) Yield(...) error {
    switch w.yieldState {
    case yieldSendBegin:
        writer := respond("data-begin")
        // ... write begin message
        yield()
        w.yieldState = yieldSendData
        return nil
        
    case yieldSendData:
        writer := respond("data-data-0")
        // ... write data
        yield()
        w.yieldState = yieldSendEnd
        return nil
        
    case yieldSendEnd:
        writer := respond("data-end")
        // ... write end message
        yield()
        w.yieldState = yieldIdle
        return nil
    }
    return nil
}
```

### Common Yield Mistakes

**❌ Forgetting to call yield():**

```go
writer := respond("message")
writer.Write(data)
// Missing yield() - protocol won't know you sent something
```

**❌ Trying to send multiple messages without yield():**

```go
respond("msg1").Write(data1)
respond("msg2").Write(data2)  // Won't work - need yield() between
```

**✅ Correct:**

```go
respond("msg1").Write(data1)
yield()
// On next Yield call:
respond("msg2").Write(data2)
yield()
```

---

## Owner vs Device Module Differences

### Owner Module Interface

```go
type OwnerModule interface {
    ProduceInfo(ctx context.Context, producer *Producer) (blockPeer, moduleDone bool, err error)
    HandleInfo(ctx context.Context, messageName string, messageBody io.Reader) error
    Transition(active bool) error
}
```

**ProduceInfo:**

- Owner sends messages to device
- Returns `blockPeer` to wait for device
- Returns `moduleDone` when finished
- Called repeatedly until done

**HandleInfo:**

- Owner receives messages from device
- Process device responses
- No return values for flow control

### Device Module Interface

```go
type DeviceModule interface {
    Receive(ctx context.Context, messageName string, messageBody io.Reader, 
            respond func(string) io.Writer, yield func()) error
    Yield(ctx context.Context, respond func(string) io.Writer, yield func()) error
    Transition(active bool) error
}
```

**Receive:**

- Device receives messages from owner
- Can respond immediately using `respond()`
- Process owner's data

**Yield:**

- Device sends messages to owner
- Initiated by device, not in response to owner
- Must call `yield()` after each message

### Key Differences

| Aspect | Owner | Device |
|--------|-------|--------|
| **Initiates** | ProduceInfo | Yield |
| **Responds** | HandleInfo | Receive |
| **Flow Control** | blockPeer, moduleDone | yield() |
| **Message Sending** | producer.WriteChunk() | respond() + yield() |
| **Blocking** | Can block device | Cannot block owner |

---

## Common Pitfalls

### 1. "Owner module did not read full body of message"

**Symptom:** TO2 fails with this error message.

**Cause:** Owner sent a message, device responded, but owner's `HandleInfo` didn't read the response body.

**Solution:**

```go
// ❌ WRONG
case "active":
    return nil  // Didn't read the body!

// ✅ CORRECT
case "active":
    var deviceActive bool
    if err := cbor.NewDecoder(messageBody).Decode(&deviceActive); err != nil {
        return err
    }
    return nil
```

### 2. Protocol Hangs Forever

**Symptom:** Test hangs, no progress, no error.

**Causes:**

- Owner blocking (blockPeer=true) but device never sends message
- Device waiting for owner but owner is also waiting
- Yield() not calling yield() after sending message

**Debug:**

- Add `slog.Debug()` statements to track state
- Check if blockPeer is being used correctly
- Verify device's Yield is being called

### 3. Module Not Receiving Messages

**Symptom:** Owner sends messages but device never receives them.

**Cause:** Device didn't advertise the module in its supported modules list.

**Solution:**

```go
// Client must register module in DeviceModules map
conf.DeviceModules = map[string]serviceinfo.DeviceModule{
    "fdo.mymodule": &fsim.MyModule{
        Handler: &myHandler{},
    },
}
```

### 4. Chunking Doesn't Work

**Symptom:** Large data transfer fails or gets corrupted.

**Causes:**

- Not sending begin/end messages
- Sending chunks out of order
- Not using ChunkReceiver/ChunkSender correctly

**Solution:** Use the chunking helpers:

```go
// Owner: Use ChunkSender
sender := chunking.NewChunkSender("data", largeData)

// Device: Use ChunkReceiver
receiver := &chunking.ChunkReceiver{PayloadName: "data"}
```

### 5. State Machine Confusion

**Symptom:** Module sends wrong messages or gets stuck in wrong state.

**Cause:** Not properly tracking state between ProduceInfo/HandleInfo calls.

**Solution:** Use explicit state enums:

```go
type myState int
const (
    stateIdle myState = iota
    stateSendingActive
    stateSendingData
    stateWaitingForResponse
)

type MyOwner struct {
    state myState
    // ...
}
```

### 6. CBOR Encoding Issues

**Symptom:** "invalid CBOR" errors or wrong data received.

**Common Mistakes:**

```go
// ❌ WRONG - Writing raw bytes
writer.Write([]byte("true"))

// ✅ CORRECT - CBOR encoding
cbor.NewEncoder(writer).Encode(true)  // Encodes as 0xf5

// ❌ WRONG - Forgetting to encode
writer.Write(myStruct)

// ✅ CORRECT
data, _ := cbor.Marshal(myStruct)
writer.Write(data)
```

---

## Quick Reference: Message Flow Patterns

### Pattern 1: Simple Parameter Setting (like SysConfig)

```
Owner: active → Device
Owner: set(param1) → Device
Owner: set(param2) → Device
Owner: done
```

**No blocking, no responses needed.**

### Pattern 2: File Transfer (like Payload)

```
Owner: active → Device
Owner: payload-begin → Device
Owner: payload-data-0 → Device
Owner: payload-data-1 → Device
Owner: payload-end → Device
Device: payload-result → Owner
Owner: done
```

**Block after payload-end to wait for result.**

### Pattern 3: Bidirectional Exchange (like WiFi with CSR)

```
Owner: active → Device
Owner: network-add → Device
[Owner blocks, device yields]
Device: csr-begin → Owner
Device: csr-data-0 → Owner
Device: csr-end → Owner
[Owner unblocks]
Owner: cert-begin → Device
Owner: cert-data-0 → Device
Owner: cert-end → Device
Device: cert-result → Owner
Owner: done
```

**Complex blocking/yielding coordination required.**

---

## Testing Tips

### 1. Start Simple

- Implement basic message sending first (like network-add)
- Don't add chunking until basic flow works
- Don't add blocking until simple flow works

### 2. Add Debug Logging

```go
slog.Debug("fdo.mymodule state", "state", w.state, "index", w.currentIndex)
```

### 3. Test Without Blocking First

- Get all messages sending/receiving correctly
- Add blockPeer only when you need bidirectional flow

### 4. Use Existing FSIMs as Reference

- **SysConfig**: Simplest pattern, no chunking, no blocking
- **Payload**: Chunking pattern, simple blocking
- **WiFi**: Complex bidirectional flow (but has issues!)

### 5. Common Test Pattern

```bash
# Test with debug logging
go run ./cmd server -db test.db -debug -mymodule-config config.json &
go run ./cmd client -di http://localhost:8080
go run ./cmd client
```

### 6. Add Timeouts to Tests

When testing bidirectional flows with blocking, always add timeouts to prevent hanging forever:

```bash
# Add timeout to prevent infinite hangs
timeout 30 go run ./cmd client
```

If your test hangs, it's usually a blocking/yielding coordination issue.

---

## Advanced Topic: Bidirectional Flow with Blocking/Yielding

### The Challenge

Implementing bidirectional flows (where device sends data to owner, then owner responds) is complex because:

1. **Owner must block** to allow device to yield
2. **Device must send across multiple Yield calls** (not all at once)
3. **Owner must unblock** when device finishes sending
4. **Timing is critical** - if either side waits forever, the protocol hangs

### Example: CSR Exchange Flow

```
1. Owner sends network-add → Device
2. Owner blocks (blockPeer=true)
3. Device yields and sends csr-begin
4. Device yields and sends csr-data-0
5. Device yields and sends csr-end
6. Owner receives csr-end, unblocks
7. Owner sends cert-begin → Device
8. Owner sends cert-data-0 → Device
9. Owner sends cert-end → Device
10. Device sends cert-result → Owner
```

### Common Mistakes in Bidirectional Flow

**❌ Mistake 1: Sending all messages in one Yield call**

```go
// WRONG - Tries to send all messages at once
func (w *Device) Yield(...) error {
    if w.needsCSR {
        respond("csr-begin").Write(beginData)
        yield()
        respond("csr-data-0").Write(csrData)
        yield()
        respond("csr-end").Write(endData)
        yield()
        w.needsCSR = false
    }
    return nil
}
```

**Problem:** Yield is called multiple times by the protocol. Each call should send ONE message, not all of them.

**✅ Solution: Use state machine**

```go
func (w *Device) Yield(...) error {
    if w.needsCSR {
        switch w.csrState {
        case 0: // Generate and prepare
            w.csrData = generateCSR()
            w.csrState = 1
            fallthrough
        case 1: // Send begin
            respond("csr-begin").Write(beginData)
            w.csrState = 2
            yield()
            return nil
        case 2: // Send data
            respond("csr-data-0").Write(w.csrData)
            w.csrState = 3
            yield()
            return nil
        case 3: // Send end
            respond("csr-end").Write(endData)
            w.csrState = 0
            w.needsCSR = false
            yield()
            return nil
        }
    }
    return nil
}
```

**❌ Mistake 2: Blocking without ensuring device will respond**

```go
// WRONG - Blocks forever if device doesn't send CSR
if network.AuthType == 3 {
    w.waitingForCSR = true
    return true, false, nil  // Blocks, but what if device can't send CSR?
}
```

**✅ Solution: Only block if you're certain device will respond**

```go
// CORRECT - Only block if we have certificates to send (meaning we expect CSR)
if network.AuthType == 3 && w.currentCertIndex < len(w.certificates) {
    w.waitingForCSR = true
    return true, false, nil  // Block and wait for CSR
}
```

**❌ Mistake 3: Not unblocking when device finishes**

```go
// WRONG - Receives CSR but doesn't unblock
case "csr-end":
    w.lastCSR = w.csrReceiver.GetBuffer()
    // Missing: w.waitingForCSR = false
    return nil
```

**✅ Solution: Unblock in HandleInfo**

```go
case "csr-end":
    w.lastCSR = w.csrReceiver.GetBuffer()
    w.waitingForCSR = false  // Unblock!
    w.sendingCert = true     // Start next phase
    return nil
```

### Simplified Approach: Skip Bidirectional Flow Initially

For initial implementation and testing:

1. **Start with one-way flow** (owner → device only)
2. **Test thoroughly** before adding bidirectional
3. **Add device → owner flow** as a separate phase
4. **Test with timeouts** to catch hangs early

Example: WiFi FSIM

- ✅ Phase 1: network-add messages (working)
- ⏸️ Phase 2: CSR exchange (complex, deferred)
- ⏸️ Phase 3: Certificate installation (depends on Phase 2)

### Debugging Bidirectional Flow Hangs

If your test hangs:

1. **Add debug logging** to track state:

```go
slog.Debug("fdo.wifi owner state", 
    "blocking", w.waitingForCSR,
    "sending_cert", w.sendingCert,
    "network_index", w.currentNetworkIndex)

slog.Debug("fdo.wifi device state",
    "needs_csr", w.needsCSR,
    "csr_state", w.csrState)
```

1. **Check if owner is blocking:**
   - Look for `blockPeer=true` returns
   - Verify device's Yield is being called

2. **Check if device is yielding:**
   - Verify `yield()` is called after each message
   - Check state machine advances correctly

3. **Add timeout to test:**

```bash
timeout 30 go run ./cmd client
```

1. **Test each direction separately:**
   - Test owner → device first
   - Test device → owner separately
   - Combine only when both work

### Key Takeaway

**Bidirectional flow is hard.** Start simple, test thoroughly, add complexity incrementally. Use timeouts to catch hangs early. Consider whether you really need bidirectional flow or if a simpler one-way pattern would work.

---

## Real-World Example: WiFi FSIM Certificate Flow

This section documents the actual problems encountered while implementing the WiFi FSIM certificate exchange, to help future developers avoid the same issues.

### Problem 1: Test Hung Forever (No Timeout)

**What Happened:**

- Implemented CSR exchange flow
- Test started but never completed
- No error message, just hung forever
- Had to manually kill the test

**Root Cause:**
Owner was blocking (`blockPeer=true`) waiting for device to send CSR, but device's Yield wasn't being called or wasn't sending correctly.

**Solution:**

```bash
# Always add timeout to tests with blocking
timeout 30 go run ./cmd client
```

**Lesson:** Add timeouts FIRST before implementing bidirectional flow. This catches coordination issues immediately instead of hanging forever.

### Problem 2: Yield Sent All Messages at Once

**What Happened:**

```go
// Device Yield tried to send all CSR messages in one call
func (w *WiFi) Yield(...) error {
    if w.needsCSR {
        respond("csr-begin").Write(beginData)
        yield()
        respond("csr-data-0").Write(csrData)
        yield()
        respond("csr-end").Write(endData)
        yield()
    }
    return nil
}
```

Test still hung because all messages were sent in the first Yield call, then subsequent Yield calls had nothing to send.

**Root Cause:**
Yield is called MULTIPLE TIMES by the protocol. Each call should send ONE message, not all of them. The `yield()` function doesn't return control - it just signals that you sent something.

**Solution:**
Use a state machine to track progress across Yield calls:

```go
func (w *WiFi) Yield(...) error {
    if w.needsCSR {
        switch w.csrState {
        case 0: // Generate CSR
            w.csrData = generateCSR()
            w.csrState = 1
            fallthrough
        case 1: // Send begin (first Yield call)
            respond("csr-begin").Write(beginData)
            w.csrState = 2
            yield()
            return nil  // Exit, wait for next Yield call
        case 2: // Send data (second Yield call)
            respond("csr-data-0").Write(w.csrData)
            w.csrState = 3
            yield()
            return nil  // Exit, wait for next Yield call
        case 3: // Send end (third Yield call)
            respond("csr-end").Write(endData)
            w.csrState = 0
            w.needsCSR = false
            yield()
            return nil
        }
    }
    return nil
}
```

**Lesson:** Yield is called repeatedly. Use state to track which message to send on each call.

### Problem 3: Owner Blocked but Never Unblocked

**What Happened:**
Owner sent network-add, then blocked waiting for CSR. Device sent CSR successfully. But owner stayed blocked and test hung.

**Root Cause:**
Owner's `HandleInfo` received the CSR messages but didn't set `waitingForCSR = false` to unblock.

**Solution:**

```go
func (w *WiFiOwner) handleCSR(messageName string, messageBody io.Reader) error {
    // ... handle CSR messages ...
    
    if messageName == "csr-end" && !w.csrReceiver.IsReceiving() {
        w.lastCSR = w.csrReceiver.GetBuffer()
        w.waitingForCSR = false  // CRITICAL: Unblock!
        w.sendingCert = true     // Start next phase
    }
    return nil
}
```

**Lesson:** When you block, you MUST unblock in HandleInfo when the expected message arrives. Otherwise the protocol hangs forever.

### Problem 4: Blocking When Device Won't Respond

**What Happened:**

```go
// Owner blocks after sending enterprise network
if network.AuthType == 3 {
    w.waitingForCSR = true
    return true, false, nil  // Blocks forever if no cert configured
}
```

Test hung because we blocked expecting CSR, but we hadn't configured any certificates, so device had no reason to send CSR.

**Root Cause:**
Blocking without verifying the device will actually respond.

**Solution:**

```go
// Only block if we have certificates to send (meaning we expect CSR)
if network.AuthType == 3 && w.currentCertIndex < len(w.certificates) {
    w.waitingForCSR = true
    return true, false, nil  // Safe to block - we know device will respond
}
```

**Lesson:** Only block if you're CERTAIN the device will respond. Add conditions to verify the response is expected.

### Problem 5: TO2 Failed After Networks Sent

**What Happened:**

- Networks were received successfully
- Device displayed all 3 networks
- Then TO2 failed with generic error
- No specific error message

**Root Cause:**
Owner tried to send certificate but the certificate sending code had bugs (wrong method calls, incomplete state management).

**Solution:**
Disable certificate sending until network-add flow is solid:

```go
// Temporarily disable cert sending
if network.AuthType == 3 && w.currentCertIndex < len(w.certificates) {
    // w.sendingCert = true  // Disabled for now
    slog.Debug("fdo.wifi skipping certificate for now")
}
```

**Lesson:** Get the basic flow working FIRST. Add complexity incrementally. Don't try to implement everything at once.

### Recommended Implementation Order

Based on these problems, here's the recommended order for implementing bidirectional FSIM:

1. **Phase 1: One-way flow (Owner → Device)**
   - Implement basic message sending
   - Test thoroughly with timeout
   - Verify all messages received correctly
   - ✅ WiFi network-add: WORKING

2. **Phase 2: Device → Owner (without blocking)**
   - Implement device Yield with state machine
   - Test device can send messages
   - Don't block owner yet
   - ⏸️ WiFi CSR sending: INFRASTRUCTURE READY

3. **Phase 3: Add blocking/unblocking**
   - Owner blocks after sending trigger message
   - Device yields and sends response
   - Owner unblocks in HandleInfo
   - Test with timeout and debug logging
   - ⏸️ WiFi CSR exchange: DEFERRED

4. **Phase 4: Owner response to device**
   - Owner sends response after receiving device data
   - Device receives and processes
   - ⏸️ WiFi certificate installation: DEFERRED

### Debug Checklist for Hanging Tests

If your test hangs with timeout:

- [ ] Added `timeout 30` to test command?
- [ ] Owner blocking? Check `blockPeer=true` returns
- [ ] Owner unblocking? Check `waitingFor* = false` in HandleInfo
- [ ] Device using state machine in Yield?
- [ ] Device calling `yield()` after each message?
- [ ] Added debug logging to track state?
- [ ] Tested one-way flow first?
- [ ] Verified device will actually respond before blocking?

### Final Takeaway

The WiFi FSIM certificate flow taught us that **bidirectional coordination is the hardest part of FSIM development**. The basic message sending/receiving is straightforward. The blocking/yielding dance is where things break.

**Start simple. Add timeouts. Use state machines. Test incrementally.**

---

## WiFi Certificate Flow: Additional Lessons Learned

After implementing the WiFi FSIM certificate flow, several critical issues were discovered and resolved. This section documents the solutions.

### Problem 6: CBOR Integer Type Decoding Failure

**What Happened:**

- All network fields decoded correctly (Version, NetworkID, SSID, Password)
- But AuthType and TrustLevel always showed as 0, regardless of actual values
- JSON config had auth_type: 1, 0, 3 but all displayed as 0

**Root Cause:**
CBOR encodes integers in various types depending on the value:

- Small integers: `uint8`, `int8`
- Medium integers: `uint16`, `int16`, `uint32`, `int32`
- Large integers: `uint64`, `int64`

The code only checked for `int` and `uint64`, missing all other integer types.

**Solution:**
Use a type switch to handle all possible integer types:

```go
// Wrong - only checks two types
if v, ok := networkMap[3].(int); ok {
    network.AuthType = v
} else if v, ok := networkMap[3].(uint64); ok {
    network.AuthType = int(v)
}

// Correct - handles all integer types
switch v := networkMap[3].(type) {
case int:
    network.AuthType = v
case int8:
    network.AuthType = int(v)
case int16:
    network.AuthType = int(v)
case int32:
    network.AuthType = int(v)
case int64:
    network.AuthType = int(v)
case uint:
    network.AuthType = int(v)
case uint8:
    network.AuthType = int(v)
case uint16:
    network.AuthType = int(v)
case uint32:
    network.AuthType = int(v)
case uint64:
    network.AuthType = int(v)
default:
    if networkMap[3] != nil {
        slog.Warn("unexpected type", "type", fmt.Sprintf("%T", networkMap[3]))
    }
}
```

**Lesson:** When decoding CBOR maps with integer values, always handle all integer types, not just `int` and `uint64`.

### Problem 7: Device Sending Responses - Yield vs Receive

**What Happened:**

- Tried to implement CSR sending using device's Yield method
- Created state machine to send csr-begin, csr-data, csr-end across multiple Yield calls
- Yield was called once, sent csr-begin, but never called again
- Test hung waiting for device to send remaining messages

**Root Cause:**
Misunderstood the FDO protocol pattern:

- **Yield** is for device-initiated messages (rare, mostly returns nil)
- **Receive** is where device responds to owner messages

Looking at other FSIMs (sysconfig, payload), they all return `nil` from Yield and send responses in Receive.

**Solution:**
Move CSR sending from Yield to Receive:

```go
// Wrong - trying to use Yield for responses
func (w *WiFi) Yield(...) error {
    if w.needsCSR {
        // State machine to send CSR across multiple calls
        // This doesn't work - Yield isn't called repeatedly
    }
    return nil
}

// Correct - send responses in Receive
func (w *WiFi) Receive(..., respond func(string) io.Writer, ...) error {
    if messageName == "network-add" {
        network := decodeNetwork(messageBody)
        
        // If enterprise network, send CSR immediately
        if network.AuthType == 3 {
            sendCSR(respond, csrData, ...)
        }
    }
    return nil
}
```

The `respond` function can be called multiple times within a single Receive call to send multiple response messages.

**Lesson:** Device sends responses in **Receive** method, not Yield. Yield is rarely used and typically returns nil.

### Problem 8: Data Chunks Must Be CBOR-Encoded

**What Happened:**

```
error handling device service info "fdo.wifi:csr-data-0": 
failed to decode chunk data: unsupported type: []uint8: 
only primitive int(N) types supported
```

Owner's ChunkReceiver failed when processing csr-data-0 message.

**Root Cause:**
Sent raw bytes for CSR data chunk:

```go
writer := respond("csr-data-0")
writer.Write(csrData)  // Wrong - raw bytes
```

But chunking protocol expects CBOR-encoded byte strings. Looking at ChunkSender code:

```go
// ChunkSender encodes chunks as CBOR
chunk := s.Data[s.bytesSent : s.bytesSent+chunkLen]
cbor.NewEncoder(&buf).Encode(chunk)  // CBOR encoding!
```

**Solution:**
CBOR-encode the data chunk:

```go
writer := respond("csr-data-0")
cbor.NewEncoder(writer).Encode(csrData)  // Correct - CBOR-encoded
```

**Lesson:** All chunked data messages (payload-data-N, csr-data-N, cert-data-N) must be CBOR-encoded byte strings, not raw bytes.

### Problem 9: Device Must Handle Certificate Messages

**What Happened:**

- CSR sent successfully (begin, data, end)
- TO2 immediately failed with generic error
- No specific error message

**Root Cause:**
Device's Receive method only handled `active` and `network-add`:

```go
func (w *WiFi) Receive(..., messageName string, ...) error {
    if messageName == "active" {
        // handle active
    }
    if messageName == "network-add" {
        // handle network-add
    }
    // Silently ignore unknown messages
    return nil
}
```

When owner tried to send certificate messages (`cert-begin`, `cert-data-0`, `cert-end`), device ignored them, causing protocol failure.

**Solution:**
Add certificate message handling:

```go
func (w *WiFi) Receive(..., messageName string, ...) error {
    if messageName == "active" {
        // handle active
    }
    if messageName == "network-add" {
        // handle network-add
    }
    if strings.HasPrefix(messageName, "cert-") {
        return w.handleCertificate(messageName, messageBody, respond)
    }
    return nil
}

func (w *WiFi) handleCertificate(messageName string, messageBody io.Reader, respond func(string) io.Writer) error {
    if w.certReceiver == nil {
        w.certReceiver = &chunking.ChunkReceiver{
            PayloadName: "cert",
            OnBegin:     w.onCertBegin,
            OnChunk:     w.onCertChunk,
            OnEnd:       w.onCertEnd,
        }
    }
    
    if err := w.certReceiver.HandleMessage(messageName, messageBody); err != nil {
        return err
    }
    
    // After cert-end, send result
    if messageName == "cert-end" && !w.certReceiver.IsReceiving() {
        resultMsg := chunking.ResultMessage{StatusCode: 0, Message: "Success"}
        resultData, _ := resultMsg.MarshalCBOR()
        respond("cert-result").Write(resultData)
    }
    
    return nil
}
```

**Lesson:** Device must handle ALL message types it expects to receive. Use ChunkReceiver for chunked messages (payload, cert, ca-bundle).

### Problem 10: Duplicate cert-begin Sends

**What Happened:**
After fixing all previous issues, the certificate flow still failed. Debug logs showed:

```
[14:21:05] DEBUG: fdo.wifi sent cert-begin
[14:21:05] DEBUG: fdo.wifi sent cert-begin  // Duplicate!
```

Owner was sending cert-begin twice, causing protocol failure.

**Root Cause:**
The sendCertificate method used `GetBytesSent() == 0` to check if begin should be sent:

```go
if w.certSender.GetBytesSent() == 0 {
    w.certSender.SendBegin(producer)
    return false, false, nil
}
```

But `SendBegin()` doesn't increment the bytes sent counter - it only sends the begin message. So on the next ProduceInfo call, `GetBytesSent()` was still 0, causing cert-begin to be sent again.

**Solution:**
Add a flag to track whether begin has been sent:

```go
// In WiFiOwner struct
certBeginSent bool

// In sendCertificate method
if w.certSender == nil {
    // Initialize sender
    w.certSender = chunking.NewChunkSender("cert", cert.CertData)
    w.certBeginSent = false  // Reset for new certificate
}

if !w.certBeginSent {
    w.certSender.SendBegin(producer)
    w.certBeginSent = true  // Mark as sent
    return false, false, nil
}
```

**Lesson:** When using ChunkSender, don't rely on `GetBytesSent()` to check if begin has been sent. Use a separate flag to track begin message state.

### Current Status: WiFi Certificate Flow ✅ WORKING

**Complete End-to-End Flow:**

1. ✅ Server loads WiFi config with 3 networks (WPA2-PSK, Open, Enterprise)
2. ✅ Owner sends network-add for all networks
3. ✅ Device receives and decodes all fields correctly (AuthType, TrustLevel, etc.)
4. ✅ Device detects enterprise network (AuthType: 3)
5. ✅ Device generates fake CSR (265 bytes)
6. ✅ Device sends CSR via chunking (csr-begin, csr-data-0, csr-end)
7. ✅ Owner receives CSR and unblocks
8. ✅ Owner sends certificate via chunking (cert-begin, cert-data-0, cert-end)
9. ✅ Device receives certificate (249 bytes)
10. ✅ Device sends cert-result (success)
11. ✅ TO2 completes successfully
12. ✅ **Test PASSES: "WiFi FSIM test PASSED"**

**Test Output:**

```
[fdo.wifi] Received certificate for network net-003 (Enterprise-WiFi)
[fdo.wifi] Certificate size: 249 bytes
[fdo.wifi] Certificate installed successfully (fake)
Success
✓ TO1/TO2 completed with WiFi network-add
✓ WiFi FSIM test PASSED
```

---

---

## CBOR Encoding in Chunking: Protocol Requirement

### Why Chunking Code Always Uses CBOR

**Question:** Why does the chunking code CBOR-encode data chunks? Can't we just send raw binary?

**Answer:** No. The FDO protocol **mandates** CBOR encoding for all ServiceInfo values.

**FDO Specification (FIDO-IoT-spec.bs, lines 5668-5687):**

```cddl
ServiceInfoKV = [
    ServiceInfoKey: tstr,
    ServiceInfoVal: bstr .cbor any
]
```

**Spec text:**
> "ServiceInfo values consist of any single CBOR base type, wrapped in a bstr. The bstr wrapping ensures that the entry can be skipped even if the major type 6 sub-type is unknown."

**What this means:**

- ALL ServiceInfo message values MUST be `bstr .cbor any`
- This is a CBOR byte string (bstr) containing CBOR-encoded data
- The inner content can be any CBOR type (int, string, array, map, bytes, etc.)
- This is a **protocol requirement**, not an implementation choice

**Why the spec requires this:**

- Forward compatibility - unknown message types can be skipped without parsing
- Protocol parsers can extract the bstr wrapper without understanding inner content
- Modules can decode their own message formats independently

### What Data Can Be Passed to Chunking Code?

**ChunkSender/ChunkReceiver accept:** `[]byte` only

**What you CAN pass:**

- ✅ Binary files (firmware images, videos, archives)
- ✅ Certificates (DER or PEM encoded)
- ✅ CSRs (DER or PEM encoded)
- ✅ Text files
- ✅ Pre-serialized CBOR data
- ✅ Any data already in byte form

**What you CANNOT pass directly:**

- ❌ Go structs
- ❌ Go maps
- ❌ Go arrays
- ❌ Any structured data that isn't already serialized

**Why this restriction?**
Chunking is designed for **bulk binary data transfer**. Structured control messages (like `network-add`, `active`, etc.) should be sent as single ServiceInfo messages without chunking.

### How Data Flows Through Chunking

**For chunked binary data (certificates, firmware, etc.):**

```go
// 1. Start with binary data
certData := []byte("-----BEGIN CERTIFICATE-----\n...")

// 2. Pass to chunking code
sender := chunking.NewChunkSender("cert", certData)

// 3. Chunking code does:
chunk := certData[0:1014]                    // Extract chunk
cbor.Encode(chunk)                           // Encode as CBOR bstr (protocol requirement)
producer.WriteChunk("cert-data-0", encoded)  // Send as ServiceInfo value

// 4. On wire: bstr .cbor bstr (outer wrapper + inner chunk bytes)
```

**For structured messages (network configuration, etc.):**

```go
// 1. Create structured data
networkMap := make(map[int]any)
networkMap[0] = "1.0"
networkMap[3] = 3  // AuthType

// 2. Serialize to bytes FIRST
var buf bytes.Buffer
cbor.NewEncoder(&buf).Encode(networkMap)

// 3. Send as single ServiceInfo message (no chunking)
producer.WriteChunk("network-add", buf.Bytes())

// 4. On wire: bstr .cbor map (wrapper + CBOR map)
```

### Common Misconception: "Double Encoding"

**It may look like double encoding:**

```
Binary data → CBOR encode → ServiceInfo message → CBOR encode again
```

**But this is correct per spec:**

- **Inner encoding:** Your data as CBOR bstr (chunking code does this)
- **Outer encoding:** ServiceInfo message structure (FDO protocol does this)
- Both layers are **required by the FDO specification**

**The spec mandates:** `ServiceInfoVal: bstr .cbor any`

- The chunking code creates the `bstr .cbor` part
- The protocol layer wraps it in the ServiceInfo message

### Use Cases: When to Use Chunking vs Direct Messages

**Use ChunkSender/ChunkReceiver for:**

- Large binary payloads (>1KB)
- Files, certificates, firmware images
- Data that needs to be streamed or buffered
- Anything that benefits from progress tracking and hash verification

**Use direct ServiceInfo messages for:**

- Small structured data (<1KB)
- Control messages (active, network-add, etc.)
- Configuration parameters
- Status responses

**Example from WiFi FSIM:**

- `network-add`: Direct message (small CBOR map)
- `csr-data-0`: Chunked (CSR can be large)
- `cert-data-0`: Chunked (certificate can be large)
- `cert-result`: Direct message (small status response)

### Key Takeaway

The CBOR encoding in chunking code is **not wasteful or redundant** - it's a **protocol requirement** mandated by the FDO specification. The chunking code correctly implements `bstr .cbor any` for all data chunks, ensuring protocol compliance and forward compatibility.

---

## Debugging FSIM Failures: Systematic Approach

This section documents a systematic approach to debugging FSIM failures, based on real debugging sessions.

### The Problem: Cryptic Error Messages

FSIM failures often present as cryptic or seemingly empty errors:

- `TO2 failed` with no details
- Error messages that appear empty (e.g., `error: { }`)
- Generic "transfer ownership failed" messages

**Key Insight:** The actual error is often hidden by logging formatters or error wrapping. Always dig deeper.

### Step 1: Get the Real Error Message

**Problem:** Some logging libraries (like `devlog`) format errors in ways that hide the actual message.

**Solution:** Use `fmt.Fprintf` to stderr to see the actual error:

```go
// Temporary debug code
if err != nil {
    fmt.Fprintf(os.Stderr, "TO2 failed: %v (type: %T)\n", err, err)
    return nil, err
}
```

This reveals:

- The actual error message (not formatted by the logger)
- The error type (helps identify where it originated)

### Step 2: Common Error Messages and Their Causes

#### "owner module did not read full body of message 'fdo.xxx:yyy'"

**Cause:** The owner's `HandleInfo` method returned without reading the entire `messageBody`.

**The Rule:** `HandleInfo` **MUST** read the entire message body before returning, even if ignoring the message.

**Fix:**

```go
// ❌ WRONG - doesn't read the body
func (c *MyOwner) HandleInfo(ctx context.Context, messageName string, messageBody io.Reader) error {
    slog.Debug("ignoring message", "name", messageName)
    return nil  // Body not read!
}

// ✅ CORRECT - reads and discards the body
func (c *MyOwner) HandleInfo(ctx context.Context, messageName string, messageBody io.Reader) error {
    _, _ = io.Copy(io.Discard, messageBody)  // MUST read the body
    slog.Debug("ignoring message", "name", messageName)
    return nil
}
```

**Why this matters:** The TO2 protocol verifies that all message bodies are fully consumed. If not, it fails with this error.

#### "NextModule not called"

**Cause:** The module state machine wasn't properly initialized before `Module()` was called.

**Fix:** Ensure `NextModule()` is called to initialize the first module after devmod completes.

#### "device has not activated module 'fdo.xxx'"

**Cause:** Owner sent a non-active message to a module that hasn't been activated yet.

**Fix:** Always send `active=true` before any other messages.

### Step 3: Check Both Sides

FSIM failures can originate from either side:

**Owner-side issues:**

- `HandleInfo` not reading message body
- `ProduceInfo` returning wrong `blockPeer`/`moduleDone` values
- Not sending `active` message first

**Device-side issues:**

- `Receive` not responding when expected
- `Yield` not calling `yield()` after sending
- Not handling all expected message types

**Debug both sides:**

```go
// Owner side
slog.Debug("[fdo.mymodule] Owner HandleInfo", "message", messageName)

// Device side  
slog.Debug("[fdo.mymodule] Device Receive", "message", messageName)
```

### Step 4: Trace the Message Flow

Add logging to trace the exact sequence of messages:

```go
// In ProduceInfo
slog.Debug("[fdo.mymodule] ProduceInfo", 
    "state", w.state,
    "blockPeer", blockPeer,
    "moduleDone", moduleDone)

// In HandleInfo
slog.Debug("[fdo.mymodule] HandleInfo",
    "message", messageName,
    "bodySize", /* read and count bytes */)

// In Receive
slog.Debug("[fdo.mymodule] Receive",
    "message", messageName,
    "responding", /* true if calling respond() */)
```

### Step 5: The HandleInfo Body Reading Rule

**This is the most common cause of FSIM failures.**

Every `HandleInfo` implementation must follow this pattern:

```go
func (c *MyOwner) HandleInfo(ctx context.Context, messageName string, messageBody io.Reader) error {
    switch messageName {
    case "expected-message":
        // Decode the message (this reads the body)
        var data MyDataType
        if err := cbor.NewDecoder(messageBody).Decode(&data); err != nil {
            return fmt.Errorf("decode %s: %w", messageName, err)
        }
        // Process data...
        return nil
        
    default:
        // CRITICAL: Even for ignored messages, MUST read the body
        _, _ = io.Copy(io.Discard, messageBody)
        slog.Debug("[fdo.mymodule] ignoring message", "name", messageName)
        return nil
    }
}
```

**Why decoding reads the body:** When you call `cbor.NewDecoder(messageBody).Decode(&data)`, the decoder reads from `messageBody`. This satisfies the "must read full body" requirement.

**Why ignoring still needs to read:** If you return without reading, the protocol detects unread bytes and fails.

### Step 6: Verify Test Output Carefully

When a test fails:

1. **Check which credential/message was last received** - This tells you where the failure occurred
2. **Look for partial success** - "Received credential: admin-creds" followed by failure means the first message worked
3. **Count the messages** - If you expected 3 credentials but only 1 was received, the failure is after the first

### Step 7: Server Log Analysis

The server log often contains more detail than the client error:

```bash
# Run test and capture server log
./test_examples.sh mytest 2>&1
cat /tmp/fdo_server.log | tail -50
```

If the server log is empty but the client fails, the error is likely in:

- Client-side message handling
- Protocol-level validation (like body reading)

### Debugging Checklist

When an FSIM test fails:

- [ ] Get the real error message (use `fmt.Fprintf` if needed)
- [ ] Check if `HandleInfo` reads the full message body
- [ ] Verify `active` message is sent first
- [ ] Check `blockPeer` usage (only block if device will respond)
- [ ] Verify device handles all expected message types
- [ ] Add debug logging to trace message flow
- [ ] Check server log for additional details
- [ ] Count messages received vs expected

### Real Example: Credentials FSIM Debugging

**Symptom:** Test received 1 of 3 credentials, then failed with empty-looking error.

**Debug steps:**

1. Added `fmt.Fprintf` to see actual error: `"owner module did not read full body of message 'fdo.credentials:active'"`
2. Checked `SimpleCredentialsOwner.HandleInfo` - it returned without reading the body
3. Added `io.Copy(io.Discard, messageBody)` to read and discard the body
4. Test passed with all 3 credentials received

**Root cause:** The device sends an `active` response, but the owner's `HandleInfo` ignored it without reading the body.

**Fix:** One line addition:

```go
func (c *SimpleCredentialsOwner) HandleInfo(..., messageBody io.Reader) error {
    _, _ = io.Copy(io.Discard, messageBody)  // Added this line
    slog.Debug("[fdo.credentials] Received message (ignoring)", "name", messageName)
    return nil
}
```

---

## Summary: The Golden Rules

1. **Active Message**: Owner sends, device responds, owner reads response
2. **HandleInfo MUST Read Body**: Always read the full `messageBody`, even when ignoring messages
3. **BlockPeer**: Only use when you're certain device will respond
4. **Yield**: Always call `yield()` after sending a message
5. **Chunking**: Use ChunkSender/ChunkReceiver for binary data ([]byte only)
6. **State**: Track state explicitly with enums
7. **CBOR**: Always encode/decode properly - it's a protocol requirement
8. **Start Simple**: Get basic flow working before adding complexity
9. **Debug**: Use `fmt.Fprintf` to see real errors, add logging to trace message flow

When in doubt, look at **SysConfig** for the simplest working pattern, or **Payload** for a chunking example that works.
