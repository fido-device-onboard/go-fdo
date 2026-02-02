# FDO Service Info Module: fdo.credentials

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

This specification defines the 'credentials' FDO serviceinfo module (FSIM) for provisioning authentication and authorization credentials to IoT devices during onboarding. This FSIM provides a unified framework for multiple credential types including passwords, API keys, X.509 certificates, OAuth2 credentials, SSH keys, and bearer tokens.

The credentials FSIM supports three distinct protocol flows:

1. **Provisioned Credentials** - Owner provisions shared secrets or pre-generated credentials to device
2. **Enrolled Credentials** - Device generates key material, requests signed credentials, and receives response
3. **Registered Credentials** - Device registers public keys with owner for authenticating to backend services

This specification incorporates and extends concepts from:

- **fdo.csr** - Certificate enrollment and server-generated keys
- **WiFi FSIM** - Chunked credential transfer patterns
- **OAuth2/OIDC** - Modern token-based authentication
- **SSH** - Public key authentication

## Design Principles

### Security Requirements

1. **Private keys MUST NEVER be transmitted** from owner to device, except in the explicit server-generated key flow (which is discouraged)
2. **All credential data MUST be chunked** using the generic chunking strategy to support large payloads
3. **Credentials MUST include metadata** specifying scope, expiration, and usage context
4. **Devices MUST validate** credential integrity using hash verification when provided

### Service Endpoint Association

A fundamental purpose of FDO is to set up devices to communicate with management services. This requires both:

1. **Credentials** - Authentication material (passwords, API keys, certificates, tokens)
2. **Endpoint URL** - The service location where credentials are used

The `endpoint_url` field in credential messages binds credentials to their target services. This enables:

- **Multiple service credentials** - Device receives credentials for different services (monitoring, configuration, telemetry) in a single onboarding session
- **Credential-endpoint pairing** - Each credential explicitly identifies which service it authenticates to
- **Service discovery** - Device knows where to connect without additional configuration

### Credential Scope for Multi-Application Disambiguation

In multi-stage onboarding, **multiple applications** may each run their own FDO client to obtain credentials. Without disambiguation, all applications would receive all credentials - creating security and complexity issues.

The `credential_scope` field solves this by allowing:

1. **Server-side scoping** - Owner tags each credential with a scope identifier
2. **Client-side filtering** - Applications advertise which scope(s) they handle
3. **Selective delivery** - Server only sends credentials matching the client's advertised scope

**Example Scenario:**

A device runs three applications, each with its own FDO client:

- **Monitoring agent** - needs credentials for `monitoring.example.com`
- **Config manager** - needs credentials for `config.example.com`  
- **Custom app** - needs credentials for `app.vendor.com`

The onboarding service has credentials for all three, tagged with scopes:

- `credential_scope: "monitoring"` → monitoring API key
- `credential_scope: "config"` → config service certificate
- `credential_scope: "vendor-app"` → vendor app OAuth token

When each application's FDO client connects:

- Monitoring agent advertises `fdo.credentials` with scope filter `"monitoring"` → receives only monitoring credentials
- Config manager advertises scope filter `"config"` → receives only config credentials
- Custom app advertises scope filter `"vendor-app"` → receives only its credentials

**Scope Filtering Mechanism:**

Clients indicate their scope filter in the `fdo.credentials:active` message:

```cddl
ActiveMessage = {
    0: active: bool,
    ? -1: scope_filter: tstr / [* tstr]  ; Single scope or list of scopes
}
```

If `scope_filter` is omitted, the client receives ALL credentials (backward compatible).

### Protocol Flows

The FSIM supports three distinct message exchange patterns:

**Provisioned Credentials: Owner → Device (Shared Secrets)**

- Owner provisions credentials that are shared secrets (passwords, API keys, OAuth2 client secrets)
- One-way message flow
- No device-generated artifacts required

**Enrolled Credentials: Device ↔ Owner (Asymmetric with Signed Response)**

- Device generates key pair (private key never leaves device)
- Device sends public key material (CSR, JWK) to owner
- Owner signs/processes and returns credential
- Two-way message flow with owner response

**Registered Credentials: Owner ↔ Device (Public Key Registration)**

- Owner requests device's public key for registration with backend services
- Device generates key pair (private key never leaves device)
- Device sends public key to owner
- Owner registers key with backend services so device can authenticate to them post-onboarding
- Use case: Device needs to SSH into config servers, access APIs with key-based auth, etc.

## Message Definitions

### Common Messages

| Direction | Key Name | Value Type | Meaning |
|-----------|----------|------------|---------|
| o <-> d | `fdo.credentials:active` | `bool` | Activate or deactivate the module |
| o --> d | `fdo.credentials:error` | `map` | Error indication with code and message |

### Provisioned Credentials: Owner-to-Device Provisioning

| Direction | Key Name | Value Type | Meaning |
|-----------|----------|------------|---------|
| o --> d | `fdo.credentials:credential-begin` | `map` | Begin credential provisioning (chunked) |
| o --> d | `fdo.credentials:credential-data-N` | `bstr` | Credential data chunk N |
| o --> d | `fdo.credentials:credential-end` | `map` | End credential provisioning |
| o <-- d | `fdo.credentials:credential-result` | `array` | Acknowledgment from device |

### Enrolled Credentials: Device-Initiated Request/Response

| Direction | Key Name | Value Type | Meaning |
|-----------|----------|------------|---------|
| o <-- d | `fdo.credentials:request-begin` | `map` | Begin credential request (chunked) |
| o <-- d | `fdo.credentials:request-data-N` | `bstr` | Request data chunk N (CSR, JWK, etc.) |
| o <-- d | `fdo.credentials:request-end` | `map` | End credential request |
| o --> d | `fdo.credentials:response-begin` | `map` | Begin credential response (chunked) |
| o --> d | `fdo.credentials:response-data-N` | `bstr` | Response data chunk N (cert, config, etc.) |
| o --> d | `fdo.credentials:response-end` | `map` | End credential response |
| o <-- d | `fdo.credentials:response-result` | `array` | Acknowledgment from device |

### Registered Credentials: Public Key Registration

| Direction | Key Name | Value Type | Meaning |
|-----------|----------|------------|---------|
| o --> d | `fdo.credentials:pubkey-request` | `map` | Owner requests device to send a public key |
| o <-- d | `fdo.credentials:pubkey-begin` | `map` | Begin public key registration (chunked) |
| o <-- d | `fdo.credentials:pubkey-data-N` | `bstr` | Public key data chunk N |
| o <-- d | `fdo.credentials:pubkey-end` | `map` | End public key registration |
| o --> d | `fdo.credentials:pubkey-result` | `array` | Registration result |

## Chunking Strategy

All credential data (credentials, CSRs, certificates, keys, tokens) MUST use the generic chunking pattern:

1. **Begin message** - Contains metadata (credential_id, credential_type, total_size, hash_alg, FSIM-specific fields)
2. **Data messages** - Numbered chunks (data-0, data-1, ...) containing CBOR-encoded byte strings
3. **End message** - Contains completion status and optional hash value
4. **Result message** - Acknowledgment with status code and message

**Chunk size:** Default 1014 bytes per FDO specification

**CBOR encoding:** All data chunks MUST be CBOR-encoded as `bstr` per FDO ServiceInfo requirements (FIDO-IoT-spec.bs, lines 5668-5687)

## Message Formats

### Begin Message Format

All `*-begin` messages use this structure:

```cddl
BeginMessage = {
    0: total_size: uint          ; Total payload size in bytes
    ? 1: hash_alg: tstr          ; Hash algorithm (e.g., "sha256", "sha384")
    -1: credential_id: tstr      ; Unique credential identifier
    -2: credential_type: tstr    ; Credential type (see Credential Types)
    ? -3: metadata: {* tstr => any}  ; Type-specific metadata
    ? -4: endpoint_url: tstr     ; Service endpoint URL where credential is used
    ? -5: credential_scope: tstr ; Scope/domain identifier for multi-app disambiguation
}
```

### End Message Format

All `*-end` messages use this structure:

```cddl
EndMessage = {
    0: status: uint              ; 0=success, 1=warning, 2=error
    ? 1: hash_value: bstr        ; Hash of complete payload
    ? -3: metadata: {* tstr => any}  ; Additional metadata
}
```

### Result Message Format

All `*-result` messages use this structure:

```cddl
ResultMessage = [
    status_code: uint,           ; 0=success, 1=warning, 2=error
    ? message: tstr              ; Human-readable status message
]
```

## Credential Types

### Supported Credential Types

| Type | Flow Pattern | Description |
|------|------|-------------|
| `password` | Provisioned | Username/password credentials |
| `api_key` | Provisioned | API keys or bearer tokens |
| `oauth2_client_secret` | Provisioned | OAuth2 client credentials (shared secret) |
| `bearer_token` | Provisioned | Pre-signed JWT or bearer tokens |
| `x509_cert` | Enrolled | X.509 certificate via CSR |
| `oauth2_private_key_jwt` | Enrolled | OAuth2 with private key JWT authentication |
| `server_generated_key` | Enrolled | Server-generated private key (discouraged) |
| `ssh_public_key` | Registered | SSH public key registration |

## Provisioned Credentials Flow

### Use Cases

- Username/password for system accounts
- API keys for cloud services
- OAuth2 client credentials (client_id + client_secret)
- Pre-signed JWT or bearer tokens

### Message Flow

```
Owner → Device: credential-begin
Owner → Device: credential-data-0
Owner → Device: credential-data-1 (if needed)
Owner → Device: credential-end
Device → Owner: credential-result
```

### credential-begin Message

```cddl
{
    0: total_size: uint
    ? 1: hash_alg: tstr
    -1: credential_id: tstr      ; e.g., "api-key-production"
    -2: credential_type: tstr    ; "password" | "api_key" | "oauth2_client_secret" | "bearer_token"
    ? -3: metadata: {
        ? username: tstr         ; For password type
        ? scope: tstr            ; Usage scope (e.g., "sudoers", "api.example.com")
        ? expires_at: tstr       ; ISO 8601 timestamp
        ? client_id: tstr        ; For OAuth2 client_secret type
        ? token_endpoint: tstr   ; For OAuth2 client_secret type
        * tstr => any            ; Additional type-specific fields
    }
    ? -4: endpoint_url: tstr     ; Service endpoint URL where credential is used
}
```

### Credential Data Format

**For password type:**

```json
{
    "username": "admin",
    "password": "hashed-or-plaintext",
    "hash_algorithm": "bcrypt"
}
```

**For api_key type:**

```json
{
    "api_key": "sk_live_abc123...",
    "service": "api.example.com"
}
```

**For oauth2_client_secret type:**

```json
{
    "client_id": "device-12345",
    "client_secret": "secret-abc...",
    "token_endpoint": "https://auth.example.com/token",
    "scope": "read write"
}
```

**For bearer_token type:**

```json
{
    "token": "eyJhbGciOiJSUzI1NiIs...",
    "token_type": "Bearer",
    "expires_at": "2026-12-31T23:59:59Z"
}
```

### Example: Provisioned Credentials - OAuth2 Client Credentials

```
Owner → Device:
fdo.credentials:credential-begin = {
    0: 156,
    1: "sha256",
    -1: "oauth2-api-access",
    -2: "oauth2_client_secret",
    -3: {
        "client_id": "device-001",
        "token_endpoint": "https://auth.example.com/token",
        "scope": "device:read device:write"
    },
    -4: "https://api.example.com/v1"
}

Owner → Device:
fdo.credentials:credential-data-0 = <CBOR bstr containing JSON credential data>

Owner → Device:
fdo.credentials:credential-end = {
    0: 0,
    1: h'a3b5c7...'
}

Device → Owner:
fdo.credentials:credential-result = [0, "OAuth2 credentials stored"]
```

## Enrolled Credentials Flow

### Use Cases

- X.509 certificate enrollment (CSR-based)
- OAuth2 with private key JWT authentication
- Server-generated keys (discouraged but supported)

### Message Flow

```
Device → Owner: request-begin
Device → Owner: request-data-0
Device → Owner: request-data-1 (if needed)
Device → Owner: request-end
Owner → Device: response-begin
Owner → Device: response-data-0
Owner → Device: response-data-1 (if needed)
Owner → Device: response-end
Device → Owner: response-result
```

### request-begin Message

```cddl
{
    0: total_size: uint
    ? 1: hash_alg: tstr
    -1: credential_id: tstr      ; e.g., "device-mtls-cert"
    -2: credential_type: tstr    ; "x509_cert" | "oauth2_private_key_jwt" | "server_generated_key"
    ? -3: metadata: {
        ? subject_dn: tstr       ; For x509_cert: "CN=device-001,O=Example"
        ? san: [* tstr]          ; For x509_cert: Subject Alternative Names
        ? key_usage: [* tstr]    ; For x509_cert: Key usage extensions
        ? token_endpoint: tstr   ; For oauth2_private_key_jwt
        ? scope: tstr            ; For oauth2_private_key_jwt
        * tstr => any
    }
    ? -4: endpoint_url: tstr     ; Service endpoint URL where credential is used
}
```

### Request Data Format

**For x509_cert type:**

- CSR in PKCS#10 format (DER or PEM encoded)
- Device has generated key pair, CSR contains public key

**For oauth2_private_key_jwt type:**

- Public key in JWK (JSON Web Key) format
- Device has generated key pair, will sign JWTs with private key

**For server_generated_key type:**

- Request parameters (subject DN, key algorithm, etc.)
- Owner will generate key pair and return both private key and certificate

### response-begin Message

```cddl
{
    0: total_size: uint
    ? 1: hash_alg: tstr
    -1: credential_id: tstr
    -2: credential_type: tstr
    ? -3: metadata: {
        ? cert_format: tstr      ; "pem" | "der"
        ? ca_bundle_included: bool
        ? client_id: tstr        ; For oauth2_private_key_jwt
        ? token_endpoint: tstr   ; For oauth2_private_key_jwt
        * tstr => any
    }
    ? -4: endpoint_url: tstr     ; Service endpoint URL where credential is used
}
```

### Response Data Format

**For x509_cert type:**

- Signed X.509 certificate (DER or PEM)
- Optionally followed by CA bundle (concatenated certificates)

**For oauth2_private_key_jwt type:**

```json
{
    "client_id": "device-001",
    "token_endpoint": "https://auth.example.com/token",
    "scope": "device:read device:write",
    "public_key_registered": true
}
```

**For server_generated_key type:**

- Private key (PKCS#8 format)
- Certificate (X.509 format)
- CA bundle (optional)

### Example: Enrolled Credentials - X.509 Certificate

```
Device → Owner:
fdo.credentials:request-begin = {
    0: 1024,
    1: "sha256",
    -1: "device-mtls-cert",
    -2: "x509_cert",
    -3: {
        "subject_dn": "CN=device-001,O=Example Corp",
        "san": ["device-001.example.com", "192.168.1.100"],
        "key_usage": ["digitalSignature", "keyEncipherment"]
    },
    -4: "https://api.example.com/v1"
}

Device → Owner:
fdo.credentials:request-data-0 = <CBOR bstr containing CSR>

Device → Owner:
fdo.credentials:request-end = {
    0: 0,
    1: h'csr-hash...'
}

Owner → Device:
fdo.credentials:response-begin = {
    0: 2048,
    1: "sha256",
    -1: "device-mtls-cert",
    -2: "x509_cert",
    -3: {
        "cert_format": "pem",
        "ca_bundle_included": true
    }
}

Owner → Device:
fdo.credentials:response-data-0 = <CBOR bstr containing certificate>
fdo.credentials:response-data-1 = <CBOR bstr containing CA bundle>

Owner → Device:
fdo.credentials:response-end = {
    0: 0,
    1: h'cert-hash...'
}

Device → Owner:
fdo.credentials:response-result = [0, "Certificate installed"]
```

## Registered Credentials Flow

### Use Cases

- Device registers SSH public key with management service for subsequent access (e.g., device SSHs into config servers)
- Device registers public key with any service that uses public key authentication
- IoT device identity registration with cloud platforms

### Message Flow

```
Owner → Device: pubkey-request
Device → Owner: pubkey-begin
Device → Owner: pubkey-data-0
Device → Owner: pubkey-data-1 (if needed)
Device → Owner: pubkey-end
Owner → Device: pubkey-result
```

### pubkey-request Message

The owner sends this message to request a public key from the device. The owner will register this key with backend services so the device can authenticate to them after onboarding.

```cddl
{
    -1: credential_id: tstr      ; Unique identifier for this key (e.g., "device-mgmt-key")
    -2: credential_type: tstr    ; "ssh_public_key"
    ? -3: metadata: {
        ? service_name: tstr     ; Name of service device will access (e.g., "config-server")
        ? username: tstr         ; Username account for SSH access (e.g., "admin", "root")
        ? key_type: tstr         ; Requested key type: "rsa" | "ed25519" | "ecdsa"
        ? key_size: uint         ; Requested key size (e.g., 2048, 4096 for RSA)
        * tstr => any
    }
    ? -4: endpoint_url: tstr     ; Service endpoint URL where public key will be used
}
```

### pubkey-begin Message

```cddl
{
    0: total_size: uint
    ? 1: hash_alg: tstr
    -1: credential_id: tstr      ; e.g., "device-mgmt-key"
    -2: credential_type: tstr    ; "ssh_public_key"
    ? -3: metadata: {
        ? username: tstr         ; Username account for SSH access (e.g., "admin", "root")
        ? key_type: tstr         ; "rsa" | "ed25519" | "ecdsa"
        ? comment: tstr          ; Key comment/description
        * tstr => any
    }
    ? -4: endpoint_url: tstr     ; Service endpoint URL where public key will be used
}
```

### Public Key Data Format

**For ssh_public_key type:**

- SSH public key in OpenSSH format (e.g., "ssh-rsa AAAAB3NzaC1...")
- Or SSH public key in RFC 4716 format

**Note on username field:**

The optional `username` metadata field specifies which user account the SSH key should be associated with. This is useful when:

- The target system has multiple user accounts
- SSH access must be restricted to a specific non-root user
- The device needs to authenticate as a particular service account
- Different keys are used for different users on the same system

### Example: Registered Credentials - SSH Public Key

Device registers its SSH public key so it can later SSH into management servers.

```
Owner → Device:
fdo.credentials:pubkey-request = {
    -1: "device-config-access",
    -2: "ssh_public_key",
    -3: {
        "service_name": "config-server.example.com",
        "username": "admin",
        "key_type": "ed25519"
    },
    -4: "ssh://config-server.example.com:22"
}

Device → Owner:
fdo.credentials:pubkey-begin = {
    0: 68,
    1: "sha256",
    -1: "device-config-access",
    -2: "ssh_public_key",
    -3: {
        "username": "admin",
        "key_type": "ed25519",
        "comment": "device-001 config access key"
    }
}

Device → Owner:
fdo.credentials:pubkey-data-0 = <CBOR bstr containing SSH public key>

Device → Owner:
fdo.credentials:pubkey-end = {
    0: 0,
    1: h'pubkey-hash...'
}

Owner → Device:
fdo.credentials:pubkey-result = [0, "Public key registered with config-server"]
```

## Error Handling

### Error Message Format

```cddl
ErrorMessage = {
    0: error_code: uint
    1: error_message: tstr
    ? 2: credential_id: tstr     ; Related credential ID
}
```

### Error Codes

| Code | Description | Applicable To |
|------|-------------|---------------|
| 1000 | Invalid credential type | All flows |
| 1001 | Invalid credential data | All flows |
| 1002 | Credential ID already exists | All flows |
| 1003 | Hash verification failed | All flows |
| 1004 | CSR validation failed | Enrolled (x509_cert) |
| 1005 | Certificate signing failed | Enrolled (x509_cert) |
| 1006 | Public key format invalid | Registered |
| 1007 | Unsupported credential type | All flows |
| 1008 | Metadata validation failed | All flows |
| 1009 | Credential storage failed | All flows |

## Security Considerations

### Private Key Protection

1. **Private keys MUST NEVER be transmitted from owner to device** except in the explicit `server_generated_key` flow
2. Devices MUST generate key pairs locally using cryptographically secure random number generators
3. Private keys MUST be stored securely (hardware security module, secure enclave, or encrypted storage)

### Credential Storage

1. Devices SHOULD store credentials in secure storage (TPM, secure element, encrypted filesystem)
2. Passwords SHOULD be hashed before storage
3. API keys and secrets SHOULD be encrypted at rest

### Transport Security

1. All credential data is protected by FDO's encrypted TO2 channel
2. Additional encryption MAY be applied for sensitive credentials
3. Hash verification SHOULD be used for all chunked transfers

### Credential Lifecycle

1. Credentials SHOULD include expiration timestamps
2. Devices SHOULD implement credential rotation mechanisms
3. Revoked credentials MUST be removed from device storage

## Implementation Notes

### Chunking Implementation

Implementations SHOULD use the generic chunking helpers provided by the FDO SDK:

- **ChunkSender** for sending chunked credentials from owner to device
- **ChunkReceiver** for receiving chunked credentials on device
- Use negative FSIM keys (-1 to -3) for credential metadata
- Always include `total_size` in begin messages for progress tracking

### Credential Type Extensibility

Implementations MAY support additional credential types beyond those defined in this specification. Custom types SHOULD use vendor-specific prefixes (e.g., `vendor.example:custom_type`).

### Metadata Extensibility

The metadata field in begin messages is extensible. Implementations MAY include additional fields as needed for specific use cases.

## References

- **FIDO-IoT-spec.bs** - FDO Protocol Specification (ServiceInfo requirements, lines 5668-5687)
- **fdo.csr.md** - Certificate Signing Request FSIM (EST integration, server-generated keys)
- **WiFi FSIM** - Reference implementation for chunking patterns
- **RFC 7030** - Enrollment over Secure Transport (EST)
- **RFC 2986** - PKCS #10: Certification Request Syntax
- **RFC 7517** - JSON Web Key (JWK)
- **RFC 7519** - JSON Web Token (JWT)
- **RFC 6749** - OAuth 2.0 Authorization Framework
- **RFC 4253** - SSH Transport Layer Protocol
- **RFC 5280** - X.509 Public Key Infrastructure Certificate

## Appendix: Complete Examples

### Example 1: API Key Provisioning

```
# Owner activates module
Owner → Device: fdo.credentials:active = true

# Owner provisions API key
Owner → Device: fdo.credentials:credential-begin = {
    0: 89,
    1: "sha256",
    -1: "production-api-key",
    -2: "api_key",
    -3: {
        "service_endpoint": "https://api.example.com",
        "scope": "read write",
        "expires_at": "2027-01-01T00:00:00Z"
    }
}

Owner → Device: fdo.credentials:credential-data-0 = <CBOR bstr: {"api_key": "sk_live_abc123..."}>

Owner → Device: fdo.credentials:credential-end = {0: 0, 1: h'hash...'}

Device → Owner: fdo.credentials:credential-result = [0, "API key stored"]

# Owner deactivates module
Owner → Device: fdo.credentials:active = false
```

### Example 2: X.509 Certificate with CA Bundle

```
# Device activates module
Device → Owner: fdo.credentials:active = true

# Device requests certificate
Device → Owner: fdo.credentials:request-begin = {
    0: 1024,
    1: "sha256",
    -1: "mtls-identity",
    -2: "x509_cert",
    -3: {
        "subject_dn": "CN=device-001,O=Example Corp",
        "san": ["device-001.example.com"],
        "key_usage": ["digitalSignature", "keyEncipherment"]
    }
}

Device → Owner: fdo.credentials:request-data-0 = <CBOR bstr: CSR in PEM format>

Device → Owner: fdo.credentials:request-end = {0: 0, 1: h'csr-hash...'}

# Owner returns certificate + CA bundle
Owner → Device: fdo.credentials:response-begin = {
    0: 3072,
    1: "sha256",
    -1: "mtls-identity",
    -2: "x509_cert",
    -3: {
        "cert_format": "pem",
        "ca_bundle_included": true
    }
}

Owner → Device: fdo.credentials:response-data-0 = <CBOR bstr: client certificate>
Owner → Device: fdo.credentials:response-data-1 = <CBOR bstr: intermediate CA cert>
Owner → Device: fdo.credentials:response-data-2 = <CBOR bstr: root CA cert>

Owner → Device: fdo.credentials:response-end = {0: 0, 1: h'cert-hash...'}

Device → Owner: fdo.credentials:response-result = [0, "Certificate and CA bundle installed"]

# Device deactivates module
Device → Owner: fdo.credentials:active = false
```

### Example 3: SSH Public Key Registration

```
# Device activates module
Device → Owner: fdo.credentials:active = true

# Device registers SSH public key
Device → Owner: fdo.credentials:pubkey-begin = {
    0: 564,
    1: "sha256",
    -1: "ssh-admin-access",
    -2: "ssh_public_key",
    -3: {
        "username": "admin",
        "authorized_hosts": ["server1.example.com"],
        "key_type": "ed25519"
    }
}

Device → Owner: fdo.credentials:pubkey-data-0 = <CBOR bstr: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...">

Device → Owner: fdo.credentials:pubkey-end = {0: 0, 1: h'pubkey-hash...'}

Owner → Device: fdo.credentials:pubkey-result = [0, "Public key added to authorized_keys on server1.example.com"]

# Device deactivates module
Device → Owner: fdo.credentials:active = false
```

---

**End of Specification**
