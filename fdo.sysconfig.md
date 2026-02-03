# fdo.sysconfig - System Configuration FSIM

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

## Purpose

The `fdo.sysconfig` FSIM enables configuration of essential system parameters during FDO device onboarding. This module provides a minimal, extensible mechanism for setting basic system configuration such as hostname, timezone, and time synchronization.

This FSIM is designed to configure the minimum parameters needed to make a device "network-ready" after onboarding. It is intentionally scoped to **small key/value settings**; larger artifacts (certificates, configuration bundles, scripts) SHOULD be delivered via [`fdo.payload`](./fdo.payload.md), which can describe content using MIME types and chunked transport.

## Key-Value Pairs

| FSIM Key | Direction | Value Type | Description |
| -------- | --------- | ---------- | ----------- |
| `fdo.sysconfig:active` | Bidirectional | `bool` | Module activation status |
| `fdo.sysconfig:set` | Owner → Device | `SystemParam` | Set one or more small parameters inline |
| `fdo.sysconfig:response` | Device → Owner | `Array` | Result array `[status, ?message]` per parameter |
| `fdo.sysconfig:error` | Device → Owner | `uint` | Error indication for FSIM operation failures |

## Data Structures

### SystemParam

The `SystemParam` structure is a CBOR array (list) of key/value pairs. Each pair is exactly two elements: parameter name and parameter value. Multiple pairs MAY be carried in one `SystemParam` array.

    SystemParam = [
        [ tstr parameter, tstr value ],
        [ tstr parameter, tstr value ],
        ...
    ]

**Notes:**

- Each pair is always two CBOR text strings in positional order: index 0 = parameter name, index 1 = parameter value.
- A single `fdo.sysconfig:set` message may carry one or more parameter pairs in the `SystemParam` array.
- Parameter names/values are opaque to the protocol; the device interprets and applies them.
- Using fixed-length arrays for pairs keeps encoding deterministic for ServiceInfo transport.

## Standard Parameters

| Parameter | Purpose | Typical Format |
| --- | --- | --- |
| `hostname` | Device identity on the network | Text hostname or FQDN |
| `timezone` | Local clock configuration | IANA timezone string |
| `ntp-server` | Time synchronization source | Hostname or IP address |
| `locale` | Regional formats & character encoding | POSIX locale (e.g., `en_US.UTF-8`) |
| `language` | UI/message language preference | ISO 639 / 639+3166 code |
| `wifi` | Basic Wi-Fi network credentials | JSON object (SSID, auth) |

These parameters are defined by this specification and MUST be supported by compliant implementations. Owners SHOULD restrict `fdo.sysconfig:set` payloads to short values; when the desired state requires larger data (cloud-init, PEM certificates, etc.), use `fdo.payload` with an appropriate MIME type instead.

### hostname

Sets the system hostname or fully qualified domain name (FQDN).

- **Parameter name**: `hostname`
- **Value format**: String containing a valid hostname or FQDN
- **Examples**:
  - `"device-12345"`
  - `"sensor-001.example.com"`
  - `"iot-gateway.local"`

**Implementation notes:**

- Device determines whether to treat value as simple hostname or FQDN
- Device is responsible for updating system hostname configuration
- May require updating multiple files (e.g., `/etc/hostname`, `/etc/hosts`)

### timezone

Sets the system timezone for proper time representation and logging.

- **Parameter name**: `timezone`
- **Value format**: IANA timezone database string
- **Examples**:
  - `"UTC"`
  - `"America/New_York"`
  - `"Europe/London"`
  - `"Asia/Tokyo"`

**Implementation notes:**

- Device should validate timezone string against available timezone data
- Typically involves symlinking or copying timezone data files
- Affects system logs, scheduled tasks, and time display

### ntp-server

Configures the NTP (Network Time Protocol) server for time synchronization.

- **Parameter name**: `ntp-server`
- **Value format**: Hostname or IP address of NTP server
- **Examples**:
  - `"time.google.com"`
  - `"pool.ntp.org"`
  - `"0.pool.ntp.org"`
  - `"192.168.1.1"`

**Implementation notes:**

- Device configures NTP client to use specified server
- May involve updating NTP daemon configuration files
- Device may support multiple NTP servers (send multiple `set` messages)

### locale

Sets the system locale for language, regional formats, and character encoding.

- **Parameter name**: `locale`
- **Value format**: POSIX locale string (language_TERRITORY.ENCODING)
- **Examples**:
  - `"en_US.UTF-8"`
  - `"de_DE.UTF-8"`
  - `"ja_JP.UTF-8"`
  - `"fr_FR.UTF-8"`
  - `"C"` (default/minimal locale)

**Implementation notes:**

- Device sets system-wide locale configuration
- Affects language display, date/time formatting, number formatting, currency, collation
- Typically involves updating `/etc/locale.conf`, `/etc/default/locale`, or similar
- May require locale generation (e.g., `locale-gen` on Debian/Ubuntu)
- Affects keyboard layout, character encoding, and text rendering

### language

Sets the system language (simplified alternative to full locale).

- **Parameter name**: `language`
- **Value format**: ISO 639-1 two-letter language code or ISO 639-1 with ISO 3166-1 country code
- **Examples**:
  - `"en"` (English)
  - `"en-US"` (English - United States)
  - `"de"` (German)
  - `"ja"` (Japanese)
  - `"zh-CN"` (Chinese - China)

**Implementation notes:**

- Simpler alternative to full locale specification
- Device may map to appropriate locale (e.g., `"en"` → `"en_US.UTF-8"`)
- Primarily affects UI language and message translations
- May be used in conjunction with `locale` parameter for fine-grained control

### wifi

Configures WiFi network credentials for wireless connectivity.

- **Parameter name**: `wifi`
- **Value format**: JSON object containing network credentials
- **JSON Structure**:

      {
        "ssid": "NetworkName",
        "password": "cleartext-password",
        "security": "auto"
      }

- **JSON Fields**:
  - `ssid` (required): Network SSID (Service Set Identifier)
  - `password` (optional): Network password in cleartext. Omit for open networks.
  - `security` (optional): Security type. Defaults to `"auto"` if omitted.
    - `"auto"` - Device auto-detects security type (default)
    - `"open"` - Open network, no encryption
    - `"wpa2"` - WPA2-PSK
    - `"wpa3"` - WPA3-PSK
    - `"wpa2-wpa3"` - Mixed WPA2/WPA3 mode
  - `hidden` (optional): Boolean, true if SSID is hidden. Defaults to false.
  - `priority` (optional): Integer priority for network selection. Higher values preferred.

- **Examples**:

      {"ssid": "HomeNetwork", "password": "MyPassword123"}

      {"ssid": "OfficeWiFi", "password": "SecurePass", "security": "wpa3"}

      {"ssid": "GuestNetwork", "security": "open"}

      {"ssid": "HiddenNet", "password": "secret", "hidden": true, "priority": 10}

**Implementation notes:**

- Password is transmitted in cleartext over the already-encrypted FDO channel
- Device is responsible for hashing/formatting password for OS-specific configuration (e.g., wpa_supplicant PSK)
- Multiple `wifi` parameters can be sent to configure multiple networks with different priorities
- Security type auto-detection allows devices to scan and determine appropriate settings
- Implementations SHOULD support at least WPA2-PSK and open networks
- Enterprise authentication (802.1X, RADIUS) is not covered by this parameter
- This parameter exists purely for convenience during simple onboarding scenarios. If provisioning requires certificates, EAP credentials, Hotspot 2.0, or any advanced Wi-Fi workflows, owners MUST use the dedicated [`fdo.wifi-setup`](./fdo.wifi-setup.md) FSIM instead of `fdo.sysconfig:wifi`.

**Security considerations:**

- WiFi credentials contain sensitive information
- FDO protocol encryption protects credentials in transit
- Device implementations must store credentials securely (encrypted storage, secure element, etc.)
- Consider using encrypted ServiceInfo payloads for additional protection

## Vendor-Specific Parameters

Implementations MAY support additional parameters beyond the standard set. To avoid naming conflicts, vendor-specific parameters MUST use reverse-DNS notation:

**Format**: `com.vendor.parameter-name`

**Examples**:

- `com.acme.device-color` → `"blue"`
- `org.example.power-mode` → `"low"`
- `io.mycompany.custom-config` → `"value"`

Implementations SHOULD ignore unknown parameters without generating errors, allowing for graceful degradation when devices don't support vendor-specific extensions.

## Message Details

### fdo.sysconfig:active

**Direction**: Bidirectional

Indicates whether the system parameter module is active and ready to process configuration requests.

**Device → Owner**: Device sends `true` if it supports system parameter configuration
**Owner → Device**: Owner may query device support (optional)

### fdo.sysconfig:set

**Direction**: Owner → Device

Instructs the device to set a system parameter.

**CBOR Structure**:

    {
      "parameter": "hostname",
      "value": "device-12345"
    }

**Processing**:

1. Device receives parameter name and value as opaque strings
2. Device validates parameter name (known vs. unknown)
3. Device applies parameter value using OS-specific mechanisms
4. Device sends `fdo.sysconfig:response` entries reflecting outcomes for each parameter in the message

**Multiple Parameters**: Owner may send multiple parameters in one `set` message (as multiple pairs) or multiple `set` messages; responses are per-parameter.

### fdo.sysconfig:response

**Direction**: Device → Owner

Reports the outcome of applying one or more parameters. One response entry per parameter in the corresponding `fdo.sysconfig:set`. Follows the generic `*-result` array format from the chunking strategy:

    SysconfigResponse = [
        code: uint,        ; 0=success, 1=warning, 2=error
        ? message: tstr    ; optional human-readable note (warnings/errors)
    ]

**Status Code Semantics**:

- `code = 0` (success): Parameter was successfully applied and is usable
- `code = 1` (warning): Parameter was applied but with warnings (e.g., partial application); parameter is usable
- `code = 2` (error): Parameter was NOT applied; parameter is unusable and should not be considered applied

**Message Field**:

- `message` (optional): Human-readable status description
  - For `code = 0`: MAY be omitted or contain success details
  - For `code = 1`: SHOULD describe the warning condition
  - For `code = 2`: SHOULD describe the failure cause

**Mapping examples (non-normative)**:

- Unknown parameter → `code=2`, message "unknown parameter" (NOT applied)
- Invalid value → `code=2`, message "invalid value" (NOT applied)
- Permission denied → `code=2`, message "permission denied" (NOT applied)
- Partial application → `code=1`, message "applied with fallback" (WAS applied)
- Not supported but fallback applied → `code=1`, message "using default value" (WAS applied)
- Not supported, no fallback → `code=2`, message "not supported" (NOT applied)

## Example Message Exchange

### Setting Hostname and Timezone

**Owner → Device**: Activate module

    fdo.sysconfig:active = true

**Device → Owner**: Confirm activation

    fdo.sysconfig:active = true

**Owner → Device**: Set hostname

    fdo.sysconfig:set = {
      parameter: "hostname",
      value: "sensor-001.example.com"
    }

**Owner → Device**: Set timezone

    fdo.sysconfig:set = {
      parameter: "timezone",
      value: "America/New_York"
    }

**Owner → Device**: Set NTP server

    fdo.sysconfig:set = {
      parameter: "ntp-server",
      value: "time.google.com"
    }

### Error Handling

**Owner → Device**: Set unsupported parameter

    fdo.sysconfig:set = {
      parameter: "unknown-param",
      value: "some-value"
    }

**Device → Owner**: Report error in response

    fdo.sysconfig:response = [2, "unknown parameter"]

### fdo.sysconfig:error

**Direction**: Device → Owner

Reports an error during FSIM operation (distinct from per-parameter response codes).

**CBOR Structure**: Unsigned integer error code

**Error Codes**:

- `1`: Module not supported
- `2`: Invalid request format
- `3`: Internal device error

**Processing**:

- Can be sent if the device cannot process the `fdo.sysconfig:set` message at all
- Terminates the current parameter setting operation
- Owner should not send more parameters after receiving error

### Sequence Diagrams

#### Basic Parameter Setting

    Owner                           Device
      |                               |
      | fdo.sysconfig:active(true)    |
      |------------------------------>|
      |                               | Activate module
      |                               |
      | fdo.sysconfig:set(params)     |
      |------------------------------>|
      |                               | Validate & apply parameters
      |                               |
      | fdo.sysconfig:response(codes) |
      |<------------------------------|

## Security Considerations

### Parameter Validation

Devices MUST validate parameter values before applying them to prevent:

- **Command injection**: Sanitize values used in shell commands
- **Path traversal**: Validate file paths if parameters affect filesystem
- **Resource exhaustion**: Limit parameter value lengths

### Privilege Requirements

Setting system parameters typically requires elevated privileges:

- Implementations should run with minimum necessary privileges
- Consider using capability-based security where available
- Audit all parameter changes for security monitoring

### Sensitive Parameters

Some parameters may expose sensitive information:

- Hostname may reveal organizational structure
- NTP server may reveal network topology
- Consider implications of parameter values in logs

### Vendor Parameters

Vendor-specific parameters introduce additional security considerations:

- Unknown parameters should be treated with caution
- Validate vendor parameter names match expected patterns
- Document security implications of custom parameters

## Implementation Flexibility

This specification intentionally leaves implementation details to the device:

### Device-Side Flexibility

- **Parameter Storage**: Device determines where/how to persist parameters
- **Application Method**: Device chooses OS-specific mechanisms (systemd, init scripts, direct file editing)
- **Validation**: Device may implement additional validation beyond format checking
- **Restart Requirements**: Device decides if/when to restart services or reboot
- **Rollback**: Device may implement rollback on failure (optional)
- **Idempotency**: Device should handle duplicate `set` messages gracefully

### Owner-Side Flexibility

- **Parameter Order**: Owner may send parameters in any order
- **Conditional Setting**: Owner may choose parameters based on device type
- **Validation**: Owner may validate values before sending
- **Error Handling**: Owner decides how to handle parameter setting failures

## Relationship to Other FSIMs

The `fdo.sysconfig` FSIM complements other configuration FSIMs:

- **fdo.sysconfig**: Configures basic system parameters (identity, time)
- **fdo.csr**: Configures certificates (security credentials)
- **fdo.payload**: Delivers arbitrary payloads (scripts, configs, SSH keys)

Together, these FSIMs provide the minimum configuration for a network-ready device:

1. Identity (hostname via `fdo.sysconfig`)
2. Time synchronization (timezone, NTP via `fdo.sysconfig`)
3. Security credentials (certificates via `fdo.csr`)
4. Advanced configuration (SSH keys, scripts via `fdo.payload`)

## Design Rationale

### Why These Parameters?

**hostname**: Essential for network identification, logging, SSH connections
**timezone**: Critical for accurate logging, time-based operations, certificate validation
**ntp-server**: Ensures accurate time, required for security protocols
**locale**: Required for proper text rendering, date/time/number formatting, keyboard layout
**language**: Simplified language setting for UI and message translations
**wifi**: Essential for wireless network connectivity, enables device to reach network services

### Why Opaque Strings?

Parameter names and values are treated as opaque strings to:

- Maximize portability across different operating systems
- Avoid protocol-level validation that may become outdated
- Allow device implementations to interpret values appropriately
- Support future parameter additions without protocol changes

### Why Not More Parameters?

This specification intentionally limits the standard parameter set to avoid:

- Feature creep and specification bloat
- OS-specific assumptions
- Overlap with other configuration mechanisms
- Complexity that reduces interoperability

Additional parameters can be added through vendor-specific extensions or future specification revisions.

### Large Configuration Guidance

`fdo.sysconfig` deliberately does **not** support chunking. Devices MAY reject oversized values (e.g., >1 KB) and instruct the owner to resend the material via `fdo.payload` with an appropriate MIME type (cloud-init, PEM, JSON template, etc.). This keeps `fdo.sysconfig` lightweight and focused on the core parameter set while providing a clear upgrade path for richer configuration flows.
