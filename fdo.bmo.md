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

**Notes:**

- Only `image_type` is required; all other fields are optional
- `boot_args` is the most commonly used optional field - it passes kernel command line arguments (e.g., kickstart URLs, installer options)
- `name`, `version`, and `description` are informational only - implementations may log them but are not required to act on them

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
- Verify hash when provided in `image-end`
- Report errors with appropriate codes
- Validate BIOS parameter names and values before applying
- Return appropriate response codes for each BIOS parameter

**SHOULD**:

- Support at least `application/efi` and `application/x-iso9660-image`
- Support at least `secure-boot` and `bios-password` BIOS parameters
- Validate Secure Boot signatures when Secure Boot is enabled
- Verify Secure Boot enablement won't brick the device
- Provide meaningful error messages

**MAY**:

- Support additional image types
- Support additional BIOS parameters (boot-order, vendor-specific)
- Provide boot progress indication

### Owner (Server) Requirements

**MUST**:

- Only send boot images to clients advertising `fdo.bmo`
- Specify valid image type in `image-begin`
- Send data in appropriate chunk sizes for firmware memory constraints
- Set `require_ack: true` for all image-begin messages to enable NAK fallback
- Handle BIOS response codes appropriately (especially errors)
- Enroll required certificates before enabling Secure Boot

**SHOULD**:

- Provide hash for integrity verification
- Include descriptive metadata (name, version)
- **Present multiple boot assets in preference order** (EFI → ISO → Raw disk)
- **Implement NAK fallback** - if firmware rejects first asset, try next preferred option
- Set BIOS password as final configuration step
- Log all BIOS configuration changes for audit

**Multi-Asset Strategy**:

When offering multiple boot assets, servers SHOULD:

1. **Start with most preferred format** (typically `application/efi`)
2. **Use NAK feedback** to determine firmware capabilities
3. **Progress through preference hierarchy** until firmware accepts
4. **Terminate after first successful transfer** (BMO phase ends)

This ensures firmware receives the **best boot method it supports** while maintaining broad compatibility across diverse firmware implementations.

## Security Considerations

### Secure Boot Integration

When Secure Boot is enabled, firmware MUST validate that received EFI images are signed by trusted keys before execution. The `fdo.bmo` module does not bypass Secure Boot - it only delivers the image; firmware enforces signature verification.

### Image Source Trust

The image is delivered over the FDO TO2 encrypted channel from an authenticated owner. However, the image content itself may come from various sources. Firmware implementations SHOULD:

- Log image metadata for audit purposes
- Verify image signatures when applicable
- Reject images that fail integrity checks
