# FSIM Chunking Strategy

This document defines a common pattern for transmitting large payloads inside FDO ServiceInfo Modules (FSIMs). The goal is to keep the transport rules consistent across all modules so that devices and owners can share code and expectations.

## Key Naming Pattern

Given a logical payload named `payload` in FSIM `fdo.example`, the chunking keys follow this pattern:

- `fdo.example:payload-begin` – announces the start of a transfer and provides metadata
- `fdo.example:payload-data-&lt;n&gt;` – payload chunks (0-based index embedded in key name)
- `fdo.example:payload-end` – signals completion of the transfer and may carry final metadata

All chunk keys carry CBOR values. `*-data-<n>` values MUST be CBOR byte strings (`bstr`).

FSIMs MAY also define a `*-result` key that the receiver uses to acknowledge completion of the transfer. Result messages follow a common structure described in [Result Messages](#result-messages).

## Begin Message Structure

The `*-begin` value is a CBOR map that uses small unsigned integer keys for compactness. Each optional field is addressable by its integer key:

### Table: Begin Message Fields

| Key | Field | Type | Description |
| --- | ----- | ---- | ----------- |
| 0 | `total_size` | `uint` | Total bytes that will be transmitted. If omitted, receivers treat the transfer as open-ended until `*-end` arrives. |
| 1 | `hash_alg` | `tstr` | Hash algorithm identifier (e.g., `"sha256"`, `"sha384"`). |
| 2 | `metadata` | `map` | Optional FSIM-specific metadata (format undefined at this layer). |
| 3 | `require_ack` | `bool` | If true, sender waits for `*-ack` before sending data chunks. See [Acknowledgment Gate](#acknowledgment-gate). |

Reserved Key Policy:

- Keys `0..127` (non-negative) are reserved for this generic chunking spec and future extensions.
- Individual FSIMs MAY define negative integer keys (e.g., `-1`) for their own metadata fields without risking future collisions.

#### CDDL Example

```cddl
payload-begin = {
  ? 0: uint,        ; total_size
  ? 1: tstr,        ; hash_alg
  ? 2: any,         ; metadata map (FSIM-defined)
  ? 3: bool         ; require_ack
}
```

## Data Messages

- Each `*-data-&lt;n&gt;` key conveys a consecutive slice of the payload.
- `&lt;n&gt;` MUST be a decimal integer starting at 0 and incrementing by 1 for each subsequent chunk.
- Value MUST be a CBOR `bstr` containing the raw bytes for that slice.
- Chunks SHOULD be ≤ 1014 bytes to align with typical FDO MTU limits, but smaller/larger slices are allowed if both sides agree.

Receivers MUST buffer chunks until all bytes have arrived. The expected byte count is determined by:

1. `total_size` (if provided) – once the sum of chunk lengths equals `total_size`, the payload is complete even if `*-end` has not arrived yet.
2. `*-end` without `total_size` – the transfer completes when the end message is received.

### CDDL Example

```cddl
payload-data = {
  ; key is encoded in ServiceInfo name (payload-data-n)
  payload-chunk: bstr
}
```

## End Message Structure

The `*-end` value is also a CBOR map with unsigned integer keys:

| Key | Field | Type | Description |
| --- | ----- | ---- | ----------- |
| 0 | `status` | `int` | FSIM-specific status code (e.g., 0 = success). |
| 1 | `hash_value` | `bstr` | Hash of the full payload, using the algorithm advertised in `*-begin`. |
| 2 | `message` | `tstr` | Optional human-readable note or error string. |

Reserved Key Policy mirrors the `*-begin` map: non-negative keys are owned by this spec, negative keys may be defined by FSIMs for additional metadata.

An empty map (or even an entirely absent `*-end` body) implies completion with no additional metadata, which most FSIMs interpret as success.

### CDDL Example

```cddl
payload-end = {
  ? 0: int,   ; status
  ? 1: bstr,  ; hash_value
  ? 2: tstr   ; message
}
```

### Hash Handling

- If `hash_alg` was provided in `*-begin`, the sender MAY defer `hash_value` until `*-end`. This accommodates cases where the hash can only be computed after the final chunk is generated.
- Receivers MUST verify the hash when both `hash_alg` and `hash_value` are present. Failure to validate SHOULD result in rejecting the payload.
- Any hash mismatch constitutes a **protocol-level error**. Implementations MUST surface these as TO2 ServiceInfo failures (terminating the FSIM exchange) rather than as FSIM-specific result codes.

### Length Handling

- `total_size` is optional. Senders that cannot determine the payload size upfront may omit it.
- If `total_size` is provided and the receiver observes more bytes than announced, it MUST treat the transfer as invalid.
- When `total_size` is omitted, receivers rely solely on `*-end` to determine completion.
- If the byte count at completion does not match the declared `total_size`, the discrepancy MUST be treated as the same protocol-level TO2 error described above.

## Error Handling

- If a chunk is missing or corrupted, the receiver SHOULD discard the entire transfer and report an error using the FSIM's normal error/result key.
- Senders MAY restart a transfer by reissuing `*-begin` with a new sequence of chunks.
- Re-sending a specific `*-data-<n>` chunk overwrites the previously received slice with the same index.
- Hash or length mismatches fall outside FSIM semantics and MUST abort the TO2 ServiceInfo exchange; FSIM-level result codes are reserved for application semantics after a well-formed payload is received.

## Result Messages

Many FSIM payloads expect the receiver to emit a follow-up status once the payload is applied. Chunked payloads SHOULD use a `*-result` key whose value is a CBOR array:

```cbor
[
  status_code,   // int: 0=success, 1=warning, 2=error (FSIM MAY define additional values)
  ? message      // optional tstr: human-readable description or error detail
]
```

## CDDL Example

```cddl
payload-result = [
  status-code: int,
  ? message: tstr
]
```

- The sender of the result (receiver of the payload) MUST set `status_code` appropriately.
- `message` MAY be omitted for success cases.
- FSIMs can extend this structure (e.g., add more array items) but SHOULD preserve the leading status/message order for consistency.
- Interpretation of `status_code`/`message` is FSIM-specific; e.g., "setting not applied" or "certificate rejected" are defined by that FSIM's spec.
- These `*-result` errors MUST NOT be confused with the generic FDO TO2 ServiceInfoModule error mechanism, which is reserved for protocol-level failures (timeouts, transport errors, etc.). Use TO2 errors only when the entire ServiceInfo exchange is compromised, not when a specific FSIM payload fails validation.

## Acknowledgment Gate

Some transfers benefit from explicit acceptance before data transmission begins. This is particularly useful when:

- The payload is large and the receiver may not support the content type
- The receiver needs to validate metadata (MIME type, size, permissions) before accepting data
- Multi-stage onboarding scenarios where payloads intended for one stage should not be sent to another

### Enabling the Gate

When `require_ack` (key 3) is set to `true` in the `*-begin` message, the sender MUST wait for a `*-ack` message before sending any `*-data-<n>` chunks.

### Ack Message Structure

The `*-ack` message uses a CBOR array format:

```cddl
payload-ack = [
  accepted: bool,       ; true = proceed with transfer, false = rejected
  ? reason_code: uint,  ; FSIM-specific rejection reason (when accepted=false)
  ? message: tstr       ; Human-readable explanation
]
```

| Index | Field | Type | Description |
| ----- | ----- | ---- | ----------- |
| 0 | `accepted` | `bool` | `true` to proceed, `false` to reject |
| 1 | `reason_code` | `uint` | Optional FSIM-specific code explaining rejection |
| 2 | `message` | `tstr` | Optional human-readable explanation |

### Protocol Flow

**With acknowledgment (accepted):**

```
Sender → Receiver: payload-begin { 3: true, ... }
Receiver → Sender: payload-ack [true]
Sender → Receiver: payload-data-0
Sender → Receiver: payload-data-1
...
Sender → Receiver: payload-end
Receiver → Sender: payload-result
```

**With acknowledgment (rejected):**

```
Sender → Receiver: payload-begin { 3: true, -1: "application/x-iso9660-image" }
Receiver → Sender: payload-ack [false, 1, "Unsupported MIME type"]
                   ; Transfer cancelled - no data chunks sent
```

**Without acknowledgment (backward compatible):**

```
Sender → Receiver: payload-begin { ... }  ; require_ack absent or false
Sender → Receiver: payload-data-0         ; proceeds immediately
...
```

### Requirements

- Senders MUST NOT send `*-data-<n>` chunks until `*-ack` is received when `require_ack` is true
- Receivers MUST send `*-ack` promptly after receiving a `*-begin` with `require_ack: true`
- If `*-ack` contains `accepted: false`, the sender MUST NOT send any data chunks
- The sender MAY attempt a different payload (new `*-begin`) after rejection
- Reason codes are FSIM-specific; common codes should be documented in each FSIM spec

### Implementation Notes

For library/framework implementations, this feature implies an **accept/reject callback** that applications can use to validate incoming transfers before data arrives:

```
// Pseudocode for device-side FSIM handler
type PayloadHandler interface {
    // Called when begin message arrives with require_ack=true
    // Return (true, 0, "") to accept, or (false, code, msg) to reject
    OnPayloadBeginAck(metadata BeginMessage) (accept bool, reasonCode uint, message string)
    
    // Called after transfer completes (existing callback)
    OnPayloadComplete(data []byte) error
}
```

This allows application code to inspect MIME types, sizes, or other metadata and reject transfers that don't apply to the current execution context.

## Integration Notes

- This strategy mirrors the patterns already proposed in `fdo.sysconfig` and other FSIM drafts but centralizes the rules so future modules stay consistent.
- FSIM specifications should reference this document instead of redefining chunk semantics. They only need to specify the logical payload names (e.g., `cert-res`, `payload`, `config-file`) and the meaning of optional metadata or result structures.
- Devices SHOULD implement generic helpers that accept a namespace/payload name and assemble chunks automatically based on the key naming convention.
