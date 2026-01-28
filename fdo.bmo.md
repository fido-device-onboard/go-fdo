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

The `fdo.bmo` (Bare Metal Onboarding) FSIM enables delivery of bootable images to device firmware for OS installation. This module is functionally similar to `fdo.payload` but serves a distinct purpose: **its presence signals to the server that the client is firmware capable of booting EFI applications or ISO images**.

## Relationship to fdo.payload

**`fdo.bmo` and `fdo.payload` are functionally identical.** Both FSIMs use the same chunking strategy, message formats, acknowledgment gate, and result handling. The *only* difference is practical deployment semantics:

| FSIM | Client Type | Payload Purpose |
|------|-------------|-----------------|
| `fdo.bmo` | UEFI firmware | Boot images (EFI, ISO) to chainload |
| `fdo.payload` | OS/Installer/Application | Scripts, configs, packages to execute/apply |

### Why Separate FSIMs?

The separation leverages **client-side FSIM advertisement as implicit phase detection**:

- A client advertising `fdo.bmo` is firmware looking for an OS installer boot image
- A client advertising `fdo.payload` has already booted and is looking for configuration data

This simplifies both client and server implementations:

- **Firmware clients** only implement `fdo.bmo` - they don't need to parse or handle configuration payloads they would never use
- **OS/application clients** only implement `fdo.payload` - they don't need boot image handling logic
- **Servers** can determine the client's provisioning phase purely from which FSIMs are advertised, without explicit phase negotiation

### Implementation Note

Because `fdo.bmo` and `fdo.payload` are wire-compatible, implementations MAY:

- Share underlying chunking code between both FSIMs
- Use a single generic payload delivery library with different FSIM name prefixes
- Theoretically merge them into a single FSIM (though this loses the phase detection benefit)

The MIME type in the payload's `image_type` or `mime_type` field provides the semantic distinction between boot images and configuration payloads.

### Phase Detection Summary

When a server sees a client advertising:

- **Only `fdo.bmo`**: Client is firmware waiting for a boot image
- **Only `fdo.payload`**: Client is OS/installer wanting configuration payloads
- **Both**: Client can receive either (unusual, but permitted)
- **Neither**: Client doesn't want any payloads

This enables a single onboarding service to handle multiple phases of device provisioning without explicit phase negotiation.

## Key-Value Pairs

| Key | Direction | Type | Description |
| --- | --------- | ---- | ----------- |
| `fdo.bmo:active` | Bidirectional | Boolean | Module activation status |
| `fdo.bmo:image-begin` | Owner → Device | Map | Announces boot image transfer |
| `fdo.bmo:image-ack` | Device → Owner | Array | Accept/reject image before transfer (when `require_ack` is set) |
| `fdo.bmo:image-data-<n>` | Owner → Device | Byte string | Image data chunk `n` (0-based) |
| `fdo.bmo:image-end` | Owner → Device | Map | Signals completion of image transfer |
| `fdo.bmo:image-result` | Device → Owner | Array | Final result with status/message |
| `fdo.bmo:error` | Device → Owner | Object | Error during transfer |

## Data Structures

### ImageBegin

Boot image transfers use the generic chunking strategy. `fdo.bmo` reserves the following negative keys:

```
{
  0: 524288000,                    / total_size: 500MB ISO /
  1: "sha256",                     / hash algorithm /
  -1: "application/x-iso9660-image", / image_type (required) /
  -2: "rhel-9.3-installer.iso",   / image name (optional) /
  -3: {                           / image metadata (optional) /
    "description": "RHEL 9.3 Installer",
    "version": "9.3",
    "boot_args": "inst.ks=..."
  }
}
```

#### ImageBegin Schema Extensions

| Key | Name | Type | Requirement | Description |
| --- | ---- | ---- | ----------- | ----------- |
| `-1` | image_type | tstr | **Required** | MIME type of the boot image |
| `-2` | name | tstr | Optional | Descriptive name for the image |
| `-3` | metadata | map | Optional | Boot arguments, version info, etc. |

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

## Supported Image Types

| MIME Type | Description |
|-----------|-------------|
| `application/efi` | UEFI executable application (.efi) |
| `application/vnd.efi` | Vendor-specific EFI application |
| `application/x-iso9660-image` | Bootable ISO image |
| `application/x-raw-disk-image` | Raw disk image |
| `application/x-pxe` | PXE boot image |
| `application/x-ipxe-script` | iPXE boot script |

## Error Codes

| Code | Name | Description |
| ---- | ---- | ----------- |
| 1 | Unknown Image Type | Firmware does not support the image type |
| 2 | Invalid Format | Image format is invalid or corrupted |
| 3 | Size Exceeded | Image exceeds available memory/storage |
| 4 | Boot Failed | Chainload/boot attempt failed |
| 5 | Transfer Error | Error during data transfer |
| 6 | Secure Boot Violation | Image fails Secure Boot verification |

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

### Unsupported Image Type (rejected via ack)

```
Owner → Device: fdo.bmo:image-begin {
  3: true,
  -1: "application/x-unsupported"
}
Device → Owner: fdo.bmo:image-ack [false, 1, "Image type not supported"]
                ; Transfer cancelled - no data sent
```

Owner MAY then attempt a different image type if firmware supports alternatives.

## Implementation Requirements

### Device (Firmware) Requirements

**MUST**:

- Advertise `fdo.bmo:active = true` only if capable of booting received images
- Validate image type before accepting data
- Verify hash when provided in `image-end`
- Report errors with appropriate codes

**SHOULD**:

- Support at least `application/efi` and `application/x-iso9660-image`
- Validate Secure Boot signatures when Secure Boot is enabled
- Provide meaningful error messages

**MAY**:

- Support additional image types
- Provide boot progress indication

### Owner (Server) Requirements

**MUST**:

- Only send boot images to clients advertising `fdo.bmo`
- Specify valid image type in `image-begin`
- Send data in appropriate chunk sizes for firmware memory constraints

**SHOULD**:

- Provide hash for integrity verification
- Include descriptive metadata (name, version)

## Security Considerations

### Secure Boot Integration

When Secure Boot is enabled, firmware MUST validate that received EFI images are signed by trusted keys before execution. The `fdo.bmo` module does not bypass Secure Boot - it only delivers the image; firmware enforces signature verification.

### Image Source Trust

The image is delivered over the FDO TO2 encrypted channel from an authenticated owner. However, the image content itself may come from various sources. Firmware implementations SHOULD:

- Log image metadata for audit purposes
- Verify image signatures when applicable
- Reject images that fail integrity checks

## Relationship to fdo.payload

`fdo.bmo` and `fdo.payload` share the same chunking mechanism but serve different purposes:

```
                    ┌─────────────────────────────────────────┐
                    │         Onboarding Service              │
                    │  (has boot image AND config payloads)   │
                    └─────────────────────────────────────────┘
                              │                     │
            Client advertises │                     │ Client advertises
               fdo.bmo        │                     │    fdo.payload
                              ▼                     ▼
                    ┌─────────────┐       ┌─────────────────┐
                    │  Firmware   │       │  OS/Installer   │
                    │  receives   │       │    receives     │
                    │ boot image  │       │  config payload │
                    └─────────────┘       └─────────────────┘
```

A server with complete device configuration can serve both firmware (via `fdo.bmo`) and installers (via `fdo.payload`) based solely on which FSIM each client advertises.
