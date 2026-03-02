# FDO Service Info Module: fdo.bmo

**Version:** 1.0 (Draft)
**Status:** Specification Draft

Copyright &copy; 2026 Dell Technologies and FIDO Alliance
Author: Brad Goodman, Dell Technologies

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

---

## Overview

**Module Name**: `fdo.bmo`
**Version**: 1.0
**Status**: Draft

The `fdo.bmo` (Bare Metal Onboarding) FSIM enables delivery of bootable images and BIOS configuration to device firmware. It combines payload delivery (like `fdo.payload`) with firmware settings (like `fdo.sysconfig`), but is designed exclusively for pre-OS firmware environments.

## Multi-Asset Handling and NAK Fallback

### Multiple Boot Assets Strategy

BMO FSIM can receive **multiple boot assets** in a single session. This enables sophisticated fallback strategies where the server offers different boot options and the firmware selects the first one it can handle.

#### NAK-Based Selection Process

When the server presents multiple boot assets:

1. **Server presents first asset** (most preferred option)
2. **Firmware checks MIME type compatibility**
   - If supported: Firmware sends `image-ack [true]` and receives the asset
   - If unsupported: Firmware sends `image-ack [false, 1, "Image type not supported"]`
3. **Server presents next asset** (next preferred option)
4. **Process repeats** until firmware accepts an asset
5. **First accepted asset terminates BMO phase** - firmware boots it immediately

#### Server Presentation Order

**Servers SHOULD present boot assets in order of preference:**

| Preference | Typical Asset Type | Rationale |
|------------|-------------------|-----------|
| 1 (Best) | `application/efi` | UEFI applications are lightweight, fast to boot |
| 2 | `application/x-iso9660-image` | Standard ISO boot images |
| 3 (Fallback) | `application/x-raw-disk-image` | Raw disk images (most cumbersome) |

**Example preference hierarchy:**

```text
1. UEFI App (application/efi)
   ↓ NAK if not supported
2. ISO Image (application/x-iso9660-image)
   ↓ NAK if not supported
3. Raw Disk (application/x-raw-disk-image)
   ↓ NAK if not supported
4. PXE/iPXE (last resort)
```

#### BMO Phase Termination

**Critical behavior**: The **first successfully received and executed boot asset terminates the BMO phase**:

- Firmware accepts asset via `image-ack [true]`
- Asset is transferred and verified
- Firmware sends `image-result [0, "Booting..."]`
- **Firmware immediately chainloads/boots the asset**
- **FDO session ends** - no further FSIM processing occurs

This ensures that:

- **Only one boot asset is ever executed** per FDO session
- **The best available option is used** (first in preference order)
- **No unnecessary transfers occur** after successful boot

#### Implementation Benefits

This multi-asset approach provides:

1. **Graceful degradation**: If firmware doesn't support the preferred format, it falls back automatically
2. **Broad compatibility**: Single server can support diverse firmware capabilities
3. **Optimal selection**: Firmware gets the best boot method it supports
4. **Efficient transfers**: Only one asset transferred per successful session

#### Protocol Example

```
Owner → Device: image-begin { -1: "application/x-iso9660-image", 3: true }
Device → Owner: image-ack [false, 1, "ISO not supported"]

Owner → Device: image-begin { -1: "application/efi", 3: true }
Device → Owner: image-ack [true]

[Transfer EFI application...]

Device → Owner: image-result [0, "Booting EFI app..."]
[Firmware chainloads EFI app, FDO session ends]
```

### Delivery Mode Fallback

The NAK fallback mechanism applies to **delivery modes** just as it does to MIME types. Owners MAY offer the **same image** via different delivery modes, and devices accept the first supported option.

#### Same Image, Multiple Delivery Methods

- Devices **SHOULD support all delivery modes** (inline, url, meta-url)
- Devices **MAY support only a subset** of delivery modes
- Owners present options in **preference order**; device accepts first supported option

#### Example: Owner Prefers Inline (Cached Image)

If an Onboarding Service has an image cached locally, it may prefer inline delivery (faster, no external dependency). If the device doesn't support inline for large images, the owner falls back to URL:

```text
1. Owner → Device: image-begin {
     -1: "application/x-raw-disk-image",
     -6: 0,                              // inline
     0: 524288000,                       // 500MB
     3: true
   }
   Device → Owner: image-ack [false, 3, "Image too large for inline transfer"]

2. Owner → Device: image-begin {
     -1: "application/x-raw-disk-image",
     -6: 1,                              // url (same image!)
     -7: "https://images.example.com/rhel9.dd",
     3: true
   }
   Device → Owner: image-ack [true]
   ; Device downloads from URL
```

#### Example: Owner Prefers URL (Bandwidth Savings)

Conversely, if the owner prefers URL delivery but the device (e.g., firmware without network stack) doesn't support it:

```text
1. Owner → Device: image-begin {
     -1: "application/efi",
     -6: 1,                              // url preferred
     -7: "https://images.example.com/boot.efi",
     3: true
   }
   Device → Owner: image-ack [false, 14, "URL delivery not supported"]

2. Owner → Device: image-begin {
     -1: "application/efi",
     -6: 0,                              // inline fallback
     3: true
   }
   Device → Owner: image-ack [true]
   ; Owner sends image-data-* chunks
```

#### Combined MIME Type and Delivery Mode Fallback

The full preference hierarchy can combine both MIME types and delivery modes:

```text
1. Try inline EFI (fastest, most compatible)
   → NAK "EFI not supported"

2. Try URL-referenced ISO (avoids large inline transfer)
   → NAK "URL delivery not supported"

3. Try inline ISO (fallback)
   → ACK, transfer begins
```

### CDN and Cloud Scaling Use Cases

#### Why URL Delivery for Scale-Out

While inline delivery is optimal for local installations (avoiding over-the-top network traffic), URL-based delivery enables **cloud and CDN scale-out**:

- **CDN Distribution**: Large images hosted on CDNs (Akamai, CloudFront, Azure CDN) can serve thousands of devices simultaneously without overloading the Onboarding Service
- **Geographic Optimization**: CDNs route devices to nearest edge nodes, reducing latency
- **Bandwidth Offload**: Onboarding Service only sends small `image-begin` messages; heavy lifting is done by CDN infrastructure
- **Cost Efficiency**: CDN bandwidth is often cheaper than direct server egress at scale

**Typical deployment pattern:**

```text
Owner (Onboarding Service)          CDN / Cloud Storage
         |                                   |
         | image-begin { url: CDN }          |
         |---------------------------------->| Device
         |                                   |
         |                                   |<-- Device fetches from CDN
         |                                   |
         | image-result [0, "success"]       |
         |<----------------------------------|
```

#### Runtime Network Accessibility Fallback

**Critical concept**: Devices may **accept** a URL-based delivery mode but **fail at runtime** when attempting to fetch. This is a normal error case, not a protocol violation.

**Common scenarios:**

- Device is on an isolated network without public internet access
- Firewall blocks outbound HTTPS to CDN domains
- DNS resolution fails for external URLs
- Network timeout due to congestion or routing issues

**Protocol behavior:**

When a device accepts URL delivery (`image-ack [true]`) but subsequently fails to fetch:

1. Device attempts to download from URL after receiving `image-end`
2. Download fails (timeout, DNS failure, connection refused, etc.)
3. Device sends `image-result` with error code 9 (URL Fetch Failed)
4. Owner MAY present an alternative delivery method (e.g., inline fallback)
5. Process continues until device successfully receives image or all options exhausted

**Example: CDN Preferred, Inline Fallback**

```text
; Owner prefers CDN for bandwidth efficiency
Owner → Device: image-begin {
  -1: "application/x-iso9660-image",
  -6: 1,                              // url
  -7: "https://cdn.example.com/rhel9.iso",
  -9: h'abc123...',
  3: true
}
Device → Owner: image-ack [true]      // Device accepts URL mode

Owner → Device: image-end {}          // Signal to fetch

; Device attempts download but fails (no internet access)
Device → Owner: image-result [9, "URL fetch failed: connection timeout"]

; Owner falls back to inline delivery (same image)
Owner → Device: image-begin {
  -1: "application/x-iso9660-image",
  -6: 0,                              // inline fallback
  3: true
}
Device → Owner: image-ack [true]

; Owner sends image-data-* chunks directly
Owner → Device: image-data-0..N
Owner → Device: image-end { 2: h'abc123...' }

Device → Owner: image-result [0, "Image received, booting"]
```

**Key points:**

- **Error code 9** (URL Fetch Failed) after `image-ack [true]` indicates runtime failure, not capability rejection
- **Owner SHOULD be prepared** to fall back to inline when URL fails
- **Device MAY retry** URL fetch before reporting failure (implementation-defined)
- **This is expected behavior** in mixed-network environments where some devices have internet access and others don't

#### Deployment Recommendations

**For large-scale deployments:**

1. **Primary**: URL delivery via CDN (scales to thousands of devices)
2. **Fallback**: Inline delivery for devices without internet access

**For isolated/air-gapped networks:**

1. **Primary**: Inline delivery (no external dependencies)
2. **Alternative**: URL to internal image server (if available)

**For mixed environments:**

1. **Primary**: URL to CDN (optimistic - most devices have internet)
2. **Fallback**: Inline (handles devices without internet access)

This approach maximizes efficiency for the common case while gracefully handling edge cases.

## Key-Value Pairs

### Module Activation

| Key | Direction | Type | Description |
| --- | --------- | ---- | ----------- |
| `fdo.bmo:active` | Bidirectional | Boolean | Module activation status |

### Image Transfer (Boot Images, Certificates)

| Key | Direction | Type | Description |
| --- | --------- | ---- | ----------- |
| `fdo.bmo:image-begin` | Owner → Device | Map | Announces image/certificate transfer |
| `fdo.bmo:image-ack` | Device → Owner | Array | Accept/reject before transfer (when `require_ack` is set) |
| `fdo.bmo:image-data-<n>` | Owner → Device | Byte string | Data chunk `n` (0-based) |
| `fdo.bmo:image-end` | Owner → Device | Map | Signals completion of transfer |
| `fdo.bmo:image-result` | Device → Owner | Array | Final result `[status, ?message]` |

### BIOS/Firmware Configuration

| Key | Direction | Type | Description |
| --- | --------- | ---- | ----------- |
| `fdo.bmo:set` | Owner → Device | Array | Set one or more BIOS parameters |
| `fdo.bmo:response` | Device → Owner | Array | Result `[status, ?message]` per parameter |

### Error Handling

| Key | Direction | Type | Description |
| --- | --------- | ---- | ----------- |
| `fdo.bmo:error` | Device → Owner | Object | Error during any operation |

## Data Structures

### ImageBegin

Boot image transfers use the generic chunking strategy. `fdo.bmo` reserves the following negative keys:

```
{
  0: 524288000,                    / total_size: 500MB ISO /
  1: "sha256",                     / hash algorithm /
  -1: "application/x-iso9660-image", / image_type (required) /
  -2: "inst.ks=http://... quiet",  / boot_args (optional) /
  -3: "rhel-9.3-installer.iso",   / name (optional) /
  -4: "9.3",                       / version (optional) /
  -5: "RHEL 9.3 Installer"         / description (optional) /
}
```

#### ImageBegin Schema Extensions

| Key | Name | Type | Requirement | Description |
| --- | ---- | ---- | ----------- | ----------- |
| `-1` | image_type | tstr | **Required** | MIME type of the boot image |
| `-2` | boot_args | tstr | Optional | Kernel/boot arguments to pass when booting the image |
| `-3` | name | tstr | Optional | Descriptive name for the image (informational) |
| `-4` | version | tstr | Optional | Version string (informational) |
| `-5` | description | tstr | Optional | Human-readable description (informational) |
| `-6` | delivery_mode | uint | Optional | 0=inline (default), 1=url, 2=meta-url. See [Delivery Modes](#delivery-modes). |
| `-7` | url | tstr | Conditional | URL to fetch image or meta-payload. Required when `delivery_mode` ≠ 0. |
| `-8` | tls_ca | bstr | Optional | Single DER-encoded CA certificate for TLS validation of URL. |
| `-9` | expected_hash | bstr | Optional | Expected hash of final image (algorithm specified in key `1`). |
| `-10` | meta_signer | bstr | Optional | COSE_Key for meta-payload signature verification. If present, meta-payload MUST be COSE Sign1. |

**Notes:**

- Only `image_type` is required; all other fields are optional
- `boot_args` is the most commonly used optional field - it passes kernel command line arguments (e.g., kickstart URLs, installer options)
- `name`, `version`, and `description` are informational only - implementations may log them but are not required to act on them
- `tls_ca` is a **single certificate** (root or intermediate CA), not a chain. This mirrors UEFI Secure Boot DB behavior where individual certificates are enrolled. Chain validation occurs at TLS handshake time using the provided CA as trust anchor.
- When `delivery_mode` is 0 (inline) or omitted, the existing chunked transfer behavior applies
- When `delivery_mode` is 1 or 2, no `image-data-*` chunks are sent; the device fetches from the URL after `image-end`

### ImageAck

When `require_ack` (key 3) is set to `true` in `image-begin`, firmware MUST respond with `image-ack` before data transfer begins. This uses the standard acknowledgment gate format from `chunking-strategy.md`:

```cddl
ImageAck = [
    accepted: bool,        ; true = proceed, false = rejected
    ? reason_code: uint,   ; Rejection reason (see Error Codes)
    ? message: tstr        ; Human-readable explanation
]
```

**Recommendation**: Owners SHOULD always set `require_ack: true` for BMO transfers since boot images are typically large and firmware capabilities vary significantly.

### ImageResult

```
[
  0,                              / status_code: 0=success /
  "Image received, booting..."    / optional message /
]
```

### BiosParam (set message)

The `set` message carries a CBOR array of parameter name/value pairs for BIOS configuration:

```cbor
[
  ["secure-boot", true],
  ["bios-password", "EnterpriseKey"]
]
```

Each pair is exactly two CBOR elements: parameter name (tstr) and parameter value (type depends on parameter).

### BiosResponse (response message)

One CBOR response per parameter in the corresponding `set` message:

```cbor
[
  0,                    / status_code: 0=success, 1=warning, 2=error /
  "Secure Boot enabled" / optional message /
]
```

### Atomicity and Error Handling

When a `set` message contains multiple parameters, firmware SHOULD apply them atomically (all-or-nothing):

- If **any** parameter fails validation or application, **all** parameters in that message SHOULD be rolled back
- This ensures the device is not left in a partially-configured state

Because atomic behavior may be difficult to guarantee in all firmware implementations, **owners SHOULD issue single key-value commands** for critical settings. This allows:

- Clear disambiguation of which parameter failed
- Simpler error handling and retry logic
- More predictable behavior across diverse firmware implementations

**Recommended pattern for critical settings:**

```
fdo.bmo:set = [["secure-boot", true]]
fdo.bmo:response = [0, "Secure Boot enabled"]

fdo.bmo:set = [["bios-password", "EnterpriseKey"]]
fdo.bmo:response = [0, "Password set"]
```

Rather than combining them in a single message.

## BIOS/Firmware Configuration

The BMO FSIM includes BIOS configuration capabilities alongside image transfer. This allows a single FSIM to handle the complete bare-metal onboarding flow: certificate enrollment, Secure Boot configuration, and boot image delivery.

**Note:** All BMO messages use CBOR encoding, consistent with the FDO protocol.

### Standard BIOS Parameters

| Parameter | Value Type | Purpose |
| --------- | ---------- | ------- |
| `secure-boot` | bool | Enable (`true`) or disable (`false`) UEFI Secure Boot |
| `bios-password` | tstr / null | Set password (string) or clear it (`null`) |
| `boot-order` | array | Set boot device priority order |

### secure-boot

Enables or disables UEFI Secure Boot.

- **Parameter name**: `secure-boot`
- **Value type**: Boolean
- **Values**: `true` (enable) or `false` (disable)

**Example:**

```
fdo.bmo:set = [["secure-boot", true]]
fdo.bmo:response = [0, "Secure Boot enabled"]
```

**Implementation notes:**

- Firmware MUST verify that enabling Secure Boot will not render the system unbootable
- If no valid boot path exists with Secure Boot enabled, firmware SHOULD reject with error
- Enabling Secure Boot typically requires valid certificates in the DB first

### bios-password

Sets or clears the BIOS/UEFI setup password.

- **Parameter name**: `bios-password`
- **Value type**: Text string or null
- **Values**: `"password-string"` (set) or `null` (clear/unlock)

**Example:**

```
fdo.bmo:set = [["bios-password", "SecureP@ss123"]]
fdo.bmo:response = [0, "Password set"]
```

**Implementation notes:**

- Password is transmitted over the already-encrypted FDO channel
- Setting a password "locks" the BIOS - users cannot modify settings without it
- Clearing the password (`null`) "unlocks" the BIOS for user modification
- Owner SHOULD set BIOS password as final step after all other configuration

### boot-order

Sets the boot device priority order.

- **Parameter name**: `boot-order`
- **Value type**: Array of strings (device identifiers)

**Example:**

```
fdo.bmo:set = [["boot-order", ["NVMe0", "PXE", "USB"]]]
fdo.bmo:response = [0, "Boot order set"]
```

### Vendor-Specific Parameters

Vendor-specific BIOS parameters use reverse-DNS notation:

- `com.dell.asset-tag` → `"ASSET12345"`
- `com.hp.virtualization` → `true`

Unknown parameters MUST be rejected with an error response.

## Delivery Modes

The `delivery_mode` field (`-6`) controls how the boot image is delivered to the device. This enables flexible deployment strategies where owners can choose between inline transfer, direct URL download, or meta-payload indirection.

### Mode 0: Inline (Default)

When `delivery_mode` is 0 or omitted, the existing chunked transfer behavior applies:

- Owner sends `image-begin` with metadata
- Owner sends `image-data-0` through `image-data-N` chunks
- Owner sends `image-end` with optional hash
- Device verifies and boots the image

This is the traditional BMO flow and remains the default for backward compatibility.

### Mode 1: Direct URL Reference

When `delivery_mode` is 1, the device fetches the image from a URL instead of receiving inline chunks:

```text
Owner → Device: image-begin {
  -1: "application/x-raw-disk-image",  // MIME type of FINAL image
  -6: 1,                                // delivery_mode = url
  -7: "https://images.example.com/rhel9.dd",
  -8: h'3082...',                       // optional: custom CA cert (DER)
  -9: h'a1b2c3...',                     // optional: expected SHA-256 hash
  1: "sha256",                          // hash algorithm (if -9 provided)
  3: true                               // require_ack
}
Device → Owner: image-ack [true]

; No image-data-* chunks sent!

Owner → Device: image-end {}            // signals "go fetch it"
Device → Owner: image-result [0, "Downloaded and verified"]
```

**Key Points:**

- **MIME type (`-1`)** describes the **final image**, not the URL
- **No new MIME types needed** - same types work for inline or URL delivery
- **TLS CA (`-8`)** is optional - if omitted, device uses system trust store
- **Hash (`-9`)** is optional - if provided, device MUST verify after download
- **Device can still NAK** based on MIME type, size concerns, or policy

### Mode 2: Meta-Payload Indirection

When `delivery_mode` is 2, the device fetches a CBOR meta-payload from the URL, which then defines the actual image location. This enables **third-party delegation** of image selection.

#### Design Rationale: Why Meta-Payloads?

Meta-payload indirection serves two key purposes:

1. **Delegate image selection to a third party** (e.g., OS vendor, image repository)
2. **Provide cryptographic integrity for unsigned image formats** (e.g., raw disk images, ISOs)

The owner specifies:

- The meta-payload URL
- The signing key for verification (optional but recommended)

The **entity controlling the meta-payload** determines which image version devices receive. This decouples fleet management from image versioning and provides a single point of control for updates.

#### Use Case 1: Vendor-Managed Images

An OS vendor (e.g., Red Hat, Canonical, Microsoft) hosts the meta-payload and controls image selection:

- Owner doesn't need to update every device's configuration when a new OS version is released
- Vendor can update the meta-payload to point to newer images
- Devices always get the "current" image as determined by the vendor

**Example**: Owner configures 10,000 devices with Red Hat's meta-URL and signing key. Red Hat updates the meta-payload when RHEL 9.4 releases. All devices automatically get the new version without owner intervention.

#### Use Case 2: Fleet Operator-Managed Images

An individual end-user or fleet operator hosts their own meta-payload to control image versions across their fleet:

**Example**: A data center operator manages 500 servers running a custom Linux image:

1. **Initial deployment**: Operator creates a meta-payload pointing to `image-v1.dd` with its SHA-256 hash, signs it with their private key, and hosts it at `https://images.mycompany.com/datacenter/meta.cbor`
2. **Fleet configuration**: All devices are configured with the meta-URL and the operator's public signing key
3. **Upgrade to v2**: When ready to upgrade, the operator:
   - Uploads `image-v2.dd` to their image server
   - Generates a new meta-payload with the v2 URL and hash
   - Signs and replaces the meta-payload at the same URL
4. **Automatic rollout**: All devices onboarding after the update automatically receive v2

This provides a **single point of control** for fleet-wide image updates without modifying device configurations or Onboarding Service settings.

#### Use Case 3: Signing Unsigned Image Formats

Many boot image formats—such as raw disk images (`dd`), ISO images, and legacy BIOS images—have **no well-defined mechanism for cryptographic signing**. The meta-payload solves this problem by providing an **external signature envelope**:

1. **Hash as signature proxy**: The meta-payload includes the expected hash of the image. Since the meta-payload itself is signed (COSE Sign1), the hash is cryptographically bound to the signer's key.
2. **Verification chain**: Device verifies meta-payload signature → extracts trusted hash → downloads image → verifies image hash matches. This effectively "signs" an image that cannot be signed internally.
3. **Easy updates**: When the image is updated (breaking the old hash), the operator simply generates a new signed meta-payload with the new hash. No changes to the image format or device configuration required.

**Example**: A raw disk image (`rhel9.dd`) cannot be signed directly. The operator:

1. Computes `sha256sum rhel9.dd` → `a1b2c3...`
2. Creates a meta-payload with `url: https://images.example.com/rhel9.dd` and `expected_hash: a1b2c3...`
3. Signs the meta-payload with their private key
4. Devices verify the signature, then verify the downloaded image matches the trusted hash

This provides **end-to-end integrity** for image formats that lack native signing support.

#### Meta-Payload Construction

Meta-payloads are constructed using a tool (TBD) that:

1. Takes the image URL, MIME type, and optional metadata as input
2. Computes the image hash (if integrity verification is desired)
3. Encodes the meta-payload as CBOR
4. Optionally wraps the payload in a COSE Sign1 structure using the operator's signing key
5. Outputs the final meta-payload for hosting at the configured URL

The meta-payload URL configured in devices may also reference the expected signing key, ensuring devices only accept meta-payloads signed by the authorized party.

#### Meta-Payload Structure (CBOR)

```cddl
MetaPayload = {
  0: tstr,           ; mime_type - MIME type of actual image
  1: tstr,           ; url - URL to fetch actual image
  ? 2: bstr,         ; tls_ca - CA cert for image URL (DER)
  ? 3: tstr,         ; hash_alg - hash algorithm
  ? 4: bstr,         ; expected_hash - hash of actual image
  ? 5: tstr,         ; boot_args - kernel arguments
  ? 6: tstr,         ; name
  ? 7: tstr,         ; version
  ? 8: tstr          ; description
}
```

#### Meta-Payload Signing (Optional COSE Sign1)

Signing is **controlled by the presence of `-10` (meta_signer)** in `image-begin`:

| `-10` Present? | Meta-Payload Format | Device Behavior |
|----------------|---------------------|-----------------|
| No | Raw CBOR `MetaPayload` | Parse directly, no signature check |
| Yes | COSE Sign1 wrapping `MetaPayload` | Verify signature, then parse payload |

**COSE Sign1 Structure** (when `-10` is present):

```cddl
COSE_Sign1 = [
  protected: bstr,    ; { 1: -7 } = ES256 (or other alg)
  unprotected: {},
  payload: bstr,      ; CBOR-encoded MetaPayload
  signature: bstr
]
```

**Device behavior when `-10` is present:**

1. Fetch meta-payload from URL
2. Parse as COSE Sign1
3. Verify signature using public key from `-10`
4. Reject if signature invalid (error code 12)
5. Extract and parse inner payload as `MetaPayload`
6. Proceed to fetch actual image

#### Protocol Flow (Meta-URL, Signed)

```text
Owner → Device: image-begin {
  -1: "application/x-bmo-meta",         // indicates meta-payload
  -6: 2,                                // delivery_mode = meta-url
  -7: "https://vendor.example.com/fleet-image.cbor",
  -10: h'a401...',                      // COSE_Key - signature required
  3: true
}
Device → Owner: image-ack [true]

Owner → Device: image-end {}

; Device fetches COSE Sign1 meta-payload, verifies signature, extracts:
; {
;   0: "application/x-raw-disk-image",
;   1: "https://images.vendor.com/rhel9-v2.dd.gz",
;   4: h'deadbeef...'
; }
; Device then fetches actual image, verifies hash, boots

Device → Owner: image-result [0, "Meta resolved, image downloaded, booting"]
```

#### Protocol Flow (Meta-URL, Unsigned)

```text
Owner → Device: image-begin {
  -1: "application/x-bmo-meta",
  -6: 2,
  -7: "https://internal.example.com/image-config.cbor",
  // No -10 = no signature verification
  3: true
}
Device → Owner: image-ack [true]

Owner → Device: image-end {}

; Device fetches raw CBOR MetaPayload (no signature wrapper)
; Parses and proceeds to fetch actual image

Device → Owner: image-result [0, "Meta resolved, image downloaded, booting"]
```

## Supported Image Types

### Boot Images

| MIME Type | Description |
|-----------|-------------|
| `application/efi` | UEFI executable application (.efi) |
| `application/vnd.efi` | Vendor-specific EFI application |
| `application/x-iso9660-image` | Bootable ISO image |
| `application/x-raw-disk-image` | Raw disk image |
| `application/x-pxe` | PXE boot image |
| `application/x-ipxe-script` | iPXE boot script |

### UEFI Secure Boot Database Operations

These image types enable enrollment of certificates into UEFI Secure Boot databases. Firmware that does not support database modification SHOULD NAK these with error code 7 (DB Modification Not Supported).

| MIME Type | Description |
|-----------|-------------|
| `application/x-uefi-db-cert` | Enroll certificate into Secure Boot DB (allowed signatures) |
| `application/x-uefi-dbx-hash` | Enroll hash into Secure Boot DBX (forbidden signatures) |
| `application/x-uefi-dbx-cert` | Enroll certificate into Secure Boot DBX (revoked certificates) |

#### DB vs DBX

| Database | Purpose | Effect | Use Case |
|----------|---------|--------|----------|
| **DB** | Allowed Signature Database | Certificates/hashes that ARE trusted for boot | Enroll enterprise signing cert to allow custom EFI apps |
| **DBX** | Forbidden Signature Database | Certificates/hashes that are REVOKED/blocked | Revoke compromised bootloaders, block known-bad hashes |

#### Certificate Enrollment Payload Format

For `application/x-uefi-db-cert` and `application/x-uefi-dbx-cert`, the payload is a DER-encoded X.509 certificate.

For `application/x-uefi-dbx-hash`, the payload is a raw SHA-256 hash (32 bytes) of the image to be blocked.

#### Security Considerations for DB/DBX Modification

**DB Enrollment** (`application/x-uefi-db-cert`):

- Adds a trusted signing certificate
- Images signed by this certificate will be allowed to boot
- **Risk**: Enrolling an untrusted cert allows arbitrary code execution
- **Mitigation**: FDO channel is authenticated; only legitimate owner can enroll

**DBX Enrollment** (`application/x-uefi-dbx-hash`, `application/x-uefi-dbx-cert`):

- Blocks specific hashes or revokes certificates
- Prevents boot of images matching the hash or signed by the revoked cert
- **Risk**: Incorrect DBX entry could brick the device (block legitimate bootloader)
- **Mitigation**: Firmware SHOULD validate that at least one valid boot path remains

#### Protocol Example: Certificate Enrollment

```
Owner → Device: fdo.bmo:image-begin {
  0: 1245,                           / cert size /
  -1: "application/x-uefi-db-cert"   / enroll to DB /
}
Device → Owner: fdo.bmo:image-ack [true]

[Transfer DER certificate...]

Device → Owner: fdo.bmo:image-result [0, "Certificate enrolled in DB"]
```

#### NAK for Unsupported DB Modification

```
Owner → Device: fdo.bmo:image-begin {
  -1: "application/x-uefi-db-cert"
}
Device → Owner: fdo.bmo:image-ack [false, 7, "DB modification not supported"]
```

## Error Codes

### Image Operation Error Codes

| Code | Name | Description |
| ---- | ---- | ----------- |
| 1 | Unknown Image Type | Firmware does not support the image type |
| 2 | Invalid Format | Image format is invalid or corrupted |
| 3 | Size Exceeded | Image exceeds available memory/storage |
| 4 | Boot Failed | Chainload/boot attempt failed |
| 5 | Transfer Error | Error during data transfer |
| 6 | Secure Boot Violation | Image fails Secure Boot verification |
| 7 | DB Modification Not Supported | Firmware cannot modify Secure Boot DB/DBX |
| 8 | DB Modification Failed | DB/DBX enrollment failed (e.g., invalid cert, policy violation) |
| 9 | URL Fetch Failed | Could not download from URL (network error, timeout, 404, etc.) |
| 10 | TLS Validation Failed | TLS certificate validation failed for URL |
| 11 | Hash Mismatch | Downloaded image hash doesn't match expected hash |
| 12 | Meta Signature Invalid | COSE Sign1 signature verification failed for meta-payload |
| 13 | Meta Parse Error | Meta-payload CBOR is malformed or missing required fields |
| 14 | Delivery Mode Not Supported | Firmware does not support the requested delivery mode (url or meta-url) |

### BIOS Parameter Error Codes

| Code | Name | Description |
| ---- | ---- | ----------- |
| 0 | Success | Parameter set successfully |
| 1 | Unknown Parameter | Parameter name not recognized |
| 2 | Invalid Value | Parameter value is invalid |
| 3 | Permission Denied | Insufficient permissions |
| 4 | Operation Failed | Generic failure |
| 5 | Not Supported | Parameter not supported by firmware |

**Note**: BIOS parameter error codes are mapped to the basic BMO response status codes (0=success, 1=warning, 2=error) in the protocol. Specific error details should be provided in the optional message field.

## Protocol Flow

### Successful Boot Image Delivery (with acknowledgment)

```
Owner                           Device (Firmware)
  |                               |
  | fdo.bmo:active = true         |
  |<------------------------------|
  |                               |
  | fdo.bmo:image-begin           |
  | { 3: true, -1: "app/efi" }    |
  |------------------------------>|
  |                               | Validate image type
  |                               |
  | fdo.bmo:image-ack [true]      |
  |<------------------------------|
  |                               |
  | fdo.bmo:image-data-0          |
  |------------------------------>|
  |         ...                   |
  | fdo.bmo:image-data-N          |
  |------------------------------>|
  |                               |
  | fdo.bmo:image-end             |
  |------------------------------>|
  |                               | Verify hash, prepare boot
  |                               |
  | fdo.bmo:image-result          |
  |<------------------------------|
  |                               |
  |         [FDO session ends]    |
  |                               |
  |         [Firmware chainloads] |
```

### Multi-Asset NAK Fallback Flow

```
Owner                           Device (Firmware)
  |                               |
  | fdo.bmo:image-begin           |
  | { 3: true, -1: "app/x-iso" }  |
  |------------------------------>|
  |                               | Check: ISO not supported
  | fdo.bmo:image-ack [false, 1, "ISO not supported"] |
  |<------------------------------|
  |                               |
  | fdo.bmo:image-begin           |
  | { 3: true, -1: "application/efi" } |
  |------------------------------>|
  |                               | Check: EFI supported!
  | fdo.bmo:image-ack [true]      |
  |<------------------------------|
  |                               |
  | fdo.bmo:image-data-0          |
  |------------------------------>|
  |         ...                   |
  | fdo.bmo:image-data-N          |
  |------------------------------>|
  |                               |
  | fdo.bmo:image-end             |
  |------------------------------>|
  |                               | Verify hash, prepare boot
  |                               |
  | fdo.bmo:image-result          |
  |<------------------------------|
  |                               |
  |         [FDO session ends]    |
  |                               |
  |         [Firmware boots EFI] |
```

### Single Asset Rejection

```
Owner → Device: fdo.bmo:image-begin {
  3: true,
  -1: "application/x-unsupported"
}
Device → Owner: fdo.bmo:image-ack [false, 1, "Image type not supported"]
                ; Transfer cancelled - no data sent
```

Owner MAY then attempt a different image type if firmware supports alternatives.

### Complete Onboarding Flow (BIOS + Boot Image)

This example shows a complete bare-metal onboarding using a single BMO FSIM session:

```
Owner                           Device (Firmware)
  |                               |
  | fdo.bmo:active = true         |
  |<------------------------------|
  |                               |
  |  Step 1: Enroll certificate to Secure Boot DB
  |                               |
  | fdo.bmo:image-begin           |
  | { -1: "application/x-uefi-db-cert" } |
  |------------------------------>|
  | fdo.bmo:image-ack [true]      |
  |<------------------------------|
  | fdo.bmo:image-data-0 (cert)   |
  |------------------------------>|
  | fdo.bmo:image-end             |
  |------------------------------>|
  | fdo.bmo:image-result [0]      |
  |<------------------------------|
  |                               |
  |  Step 2: Enable Secure Boot
  |                               |
  | fdo.bmo:set [["secure-boot", true]] |
  |------------------------------>|
  | fdo.bmo:response [0, "Secure Boot enabled"] |
  |<------------------------------|
  |                               |
  |  Step 3: Set BIOS password (lock config)
  |                               |
  | fdo.bmo:set [["bios-password", "EnterpriseKey"]] |
  |------------------------------>|
  | fdo.bmo:response [0, "Password set"] |
  |<------------------------------|
  |                               |
  |  Step 4: Deliver signed boot image
  |                               |
  | fdo.bmo:image-begin           |
  | { -1: "application/efi" }     |
  |------------------------------>|
  | fdo.bmo:image-ack [true]      |
  |<------------------------------|
  | fdo.bmo:image-data-0..N       |
  |------------------------------>|
  | fdo.bmo:image-end             |
  |------------------------------>|
  | fdo.bmo:image-result [0, "Booting..."] |
  |<------------------------------|
  |                               |
  |         [FDO session ends]    |
  |         [Firmware boots EFI]  |
```

## Implementation Requirements

### Device (Firmware) Requirements

**MUST**:

- Advertise `fdo.bmo:active = true` only if capable of booting received images
- Validate image type before accepting data
- Verify hash when provided in `image-end` or `expected_hash` (`-9`)
- Report errors with appropriate codes
- Validate BIOS parameter names and values before applying
- Return appropriate response codes for each BIOS parameter
- NAK with error code 14 if `delivery_mode` is not supported

**SHOULD**:

- Support at least `application/efi` and `application/x-iso9660-image`
- Support at least `secure-boot` and `bios-password` BIOS parameters
- Support all delivery modes (inline, url, meta-url) when network stack is available
- Validate Secure Boot signatures when Secure Boot is enabled
- Verify Secure Boot enablement won't brick the device
- Provide meaningful error messages
- Verify COSE Sign1 signatures when `meta_signer` (`-10`) is provided
- Use provided `tls_ca` (`-8`) for TLS validation when fetching from URLs

**MAY**:

- Support additional image types
- Support additional BIOS parameters (boot-order, vendor-specific)
- Provide boot progress indication
- Support URL and meta-url delivery modes (firmware without network stack may only support inline)

### Owner (Server) Requirements

**MUST**:

- Only send boot images to clients advertising `fdo.bmo`
- Specify valid image type in `image-begin`
- Send data in appropriate chunk sizes for firmware memory constraints (inline mode)
- Set `require_ack: true` for all image-begin messages to enable NAK fallback
- Handle BIOS response codes appropriately (especially errors)
- Enroll required certificates before enabling Secure Boot
- Provide `url` (`-7`) when `delivery_mode` is 1 or 2
- Send `image-end` (with no data chunks) to signal "go fetch" for URL modes

**SHOULD**:

- Provide hash for integrity verification (`expected_hash` for URL modes, `image-end` hash for inline)
- Include descriptive metadata (name, version)
- **Present multiple boot assets in preference order** (EFI → ISO → Raw disk)
- **Implement NAK fallback** - if firmware rejects first asset, try next preferred option
- **Implement delivery mode fallback** - if firmware rejects URL mode, fall back to inline
- Set BIOS password as final configuration step
- Log all BIOS configuration changes for audit
- Present preferred delivery mode first (based on caching, bandwidth, latency considerations)
- Be prepared to fall back to alternative delivery modes for the same image

**Multi-Asset and Delivery Mode Strategy**:

When offering multiple boot assets, servers SHOULD:

1. **Start with most preferred format and delivery mode** (e.g., inline EFI if cached locally)
2. **Use NAK feedback** to determine firmware capabilities (both MIME type and delivery mode)
3. **Progress through preference hierarchy** until firmware accepts
4. **Terminate after first successful transfer** (BMO phase ends)

This ensures firmware receives the **best boot method it supports** while maintaining broad compatibility across diverse firmware implementations. The same image MAY be offered via different delivery modes (e.g., inline first, then URL fallback) to accommodate varying device capabilities.

## Security Considerations

### Secure Boot Integration

When Secure Boot is enabled, firmware MUST validate that received EFI images are signed by trusted keys before execution. The `fdo.bmo` module does not bypass Secure Boot - it only delivers the image; firmware enforces signature verification.

### Image Source Trust

The image is delivered over the FDO TO2 encrypted channel from an authenticated owner. However, the image content itself may come from various sources. Firmware implementations SHOULD:

- Log image metadata for audit purposes
- Verify image signatures when applicable
- Reject images that fail integrity checks

### URL Delivery Security

When using URL-based delivery modes (1 or 2), additional security considerations apply:

**TLS Validation:**

- Devices MUST validate TLS certificates when fetching from HTTPS URLs
- If `tls_ca` (`-8`) is provided, device SHOULD use it as the trust anchor
- If `tls_ca` is not provided, device SHOULD use system trust store
- Devices MUST reject connections with invalid or expired certificates (error code 10)

**Hash Verification:**

- When `expected_hash` (`-9`) is provided, device MUST verify the downloaded image matches
- Hash verification provides end-to-end integrity even if TLS is compromised
- Devices MUST reject images with hash mismatch (error code 11)

**Meta-Payload Signing:**

- When `meta_signer` (`-10`) is provided, device MUST verify the COSE Sign1 signature
- This protects against compromised meta-payload URLs or man-in-the-middle attacks
- The signing key is delivered over the authenticated FDO channel, establishing trust
- Devices MUST reject meta-payloads with invalid signatures (error code 12)

**Network Exposure:**

- URL delivery exposes the device to external network traffic outside the FDO channel
- Firmware SHOULD minimize attack surface by:
  - Using HTTPS only (reject HTTP URLs)
  - Validating URL format before fetching
  - Implementing timeouts to prevent resource exhaustion
  - Limiting redirect following

**Third-Party Delegation Trust Model:**

When using meta-url mode with third-party vendors:

- The owner trusts the vendor by including their signing key (`-10`)
- The vendor controls image selection but cannot modify the trust relationship
- Devices verify the vendor's signature, ensuring image authenticity
- This model enables fleet-wide updates without owner intervention while maintaining security

## Tooling

### CLI: `fdo meta`

The `fdo meta` CLI subcommand provides tools for creating, signing, and verifying meta-payloads. See [CLI_COMMANDS.md](CLI_COMMANDS.md#meta-commands-bmo-meta-payload-tooling) for full documentation.

```bash
fdo meta create         # Create unsigned meta-payload CBOR
fdo meta sign           # Sign with ECDSA private key (COSE Sign1)
fdo meta verify         # Verify signature + optionally print contents
fdo meta create-signed  # Create + sign in one step
fdo meta export-pubkey  # Export public key as COSE_Key CBOR
```

### Server Flag: `-bmo-meta-url`

Configures the example server to use meta-URL delivery mode:

```bash
# Unsigned
fdo server -bmo-meta-url http://cdn.example.com/meta.cbor

# Signed (PEM key auto-converted to COSE_Key)
fdo server -bmo-meta-url "http://cdn.example.com/meta-signed.cbor:signer-key.pem"
```

### Library API: `fsim` Package

The `fsim` package provides the building blocks used by the CLI:

| Function | Description |
|----------|-------------|
| `CreateMetaPayload()` | Build CBOR `MetaPayload` with functional options |
| `SignMetaPayload()` | Wrap CBOR in COSE Sign1 envelope |
| `MarshalSignerPublicKey()` | Convert `crypto.PublicKey` → COSE_Key CBOR |
| `ComputeSHA256()` | Compute SHA-256 hash of data |
| `CoseSign1Verifier.Verify()` | Verify COSE Sign1 signature, return inner payload |

**Functional options for `CreateMetaPayload()`:** `WithBootArgs()`, `WithVersion()`, `WithDescription()`, `WithTLSCA()`.

### Integration Tests

| Test | Command | Description |
|------|---------|-------------|
| `bmo-meta-url` | `./test_examples.sh bmo-meta-url` | Unsigned meta-payload via CLI + HTTP server |
| `bmo-meta-signed` | `./test_examples.sh bmo-meta-signed` | Signed meta-payload + tampered-signature negative test |
| Scenario 8 | `bash tests/supertest/scenario-8-bmo-meta-url.sh` | Full supertest: inline + unsigned + signed + negative |
