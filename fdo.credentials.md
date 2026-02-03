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

## Implementation Responsibilities

This section clarifies the responsibilities of both device (client) and server (owner) implementations when using the credentials FSIM.

### Core Architectural Principle

**Both sides MUST have pre-established knowledge of credential types and purposes by credential ID.**

The credential ID (e.g., "device-mtls-cert", "api-access-key", "ssh-config-access") is not just an identifier - it represents a **semantic contract** between device and server about:

- What service the credential is for
- What type of credential is expected
- What level of access is appropriate
- What deployment-specific details the server will provide

### Device (Client) Responsibilities

#### 1. **Know What You Need**

- Maintain a list of credential IDs your device requires
- Understand what each credential ID means (service, purpose, type)
- Request credentials only by their established semantic IDs

#### 2. **Generate Your Own Keys** (for enrolled flows)

- For X.509 certificates: generate key pair and create CSR
- For OAuth2 JWT: generate key pair and send public key
- **NEVER** expect the server to know your private keys

#### 3. **Trust Server's Decisions**

- Accept the scope and endpoint URL provided by the server
- The server knows the deployment-specific configuration
- Do not attempt to specify your own endpoints or scopes

#### 4. **Handle Multiple Services**

- Use different credential IDs for different services
- Example: "monitoring-api-key" vs "config-api-key"
- Each ID represents a distinct service relationship

### Server (Owner) Responsibilities

#### 1. **Recognize Credential IDs**

- Maintain a mapping of credential IDs to service configurations
- Understand what each ID means in your deployment
- Be prepared to provide the appropriate credential type

#### 2. **Grant Appropriate Access**

- Decide scope based on the credential ID and your policies
- Do not trust client requests for scope - grant what's appropriate
- Apply principle of least privilege

#### 3. **Provide Deployment Details**

- Return the actual endpoint URL for the service in your deployment
- This may differ between development, staging, and production
- The device needs this to actually use the credential

#### 4. **Maintain Security Boundaries**

- Each credential ID should have a well-defined security boundary
- Do not grant cross-access between different credential IDs
- Enforce isolation between services

### Example: Multi-Service Device

A device needs credentials for two different services:

```
Device requests:
- credential_id: "telemetry-api-key" → Server grants: scope="telemetry:write", endpoint="https://telemetry.prod.example.com"
- credential_id: "config-api-key" → Server grants: scope="config:read", endpoint="https://config.prod.example.com"
```

The device doesn't specify endpoints or scopes - it trusts the server to provide the correct deployment-specific values for each semantic credential ID.

### Example: Environment-Specific Deployment

```
Development:
- credential_id: "api-access" → endpoint="https://api-dev.example.com"

Production:
- credential_id: "api-access" → endpoint="https://api.prod.example.com"
```

Same credential ID, different deployment-specific endpoint provided by the server.

### Benefits of This Architecture

1. **Clear Contracts** - Credential IDs have well-understood meanings
2. **Deployment Flexibility** - Servers can adapt to different environments
3. **Security Boundaries** - Each ID represents a specific service relationship
4. **Scalability** - Easy to add new services by defining new credential IDs
5. **Maintainability** - Changes to endpoints only require server updates

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
    ? 1: hash_alg: int           ; COSE hash algorithm identifier (e.g., -16=SHA-256, -43=SHA-384, -44=SHA-512)
    -1: credential_id: tstr      ; Unique credential identifier
    -2: credential_type: tstr    ; Credential type (see enumerated types below)
    ? -4: endpoint_url: tstr     ; Service endpoint URL where credential is used
}
```

**Credential Type Enumeration:**

The `credential_type` field MUST be one of the following values:

- `"password"` - User/password authentication credentials
- `"secret"` - Unified secret type (API keys, OAuth secrets, bearer tokens, etc.)
- `"x509_cert"` - X.509 certificate enrollment (CSR-based)
- `"server_generated_key"` - Server-generated key pairs (discouraged)
- `"ssh_public_key"` - SSH public key registration

**Note:** These types are defined exclusively within this specification. Extensions require updating this document.

**Hash Algorithm Identifiers (COSE):**

- `-16` = SHA-256 (recommended)
- `-43` = SHA-384  
- `-44` = SHA-512
- `-18` = SHAKE128
- `-45` = SHAKE256

See [IANA COSE Algorithms Registry](https://www.iana.org/assignments/cose/cose.xhtml) for complete list.

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
    ? 1: hash_alg: int           ; COSE hash algorithm identifier
    -1: credential_id: tstr      ; e.g., "api-key-production"
    -2: credential_type: CredentialType  ; 1=password, 2=secret (for provisioned)
    ? -4: endpoint_url: tstr     ; Service endpoint URL where credential is used
}
```

### Credential Data Format

**Type Definitions:**

```cddl
; Unified credential type identifiers for all flows (integers)
CredentialType = 1 / 2 / 3 / 4 / 5
; 1 = password (provisioned - PasswordCredential)
; 2 = secret (provisioned - SecretCredential)
; 3 = x509_cert (enrolled - X509CertRequest/Response)
; 4 = server_generated_key (enrolled - ServerKeyRequest/Response)
; 5 = ssh_public_key (registered - SSHPublicKey)

; Hash algorithms for password storage
HashAlgorithm = "bcrypt" / "pbkdf2" / "scrypt" / "argon2" / tstr

; Secret types for unified secret credential (suggested values)
SecretType = "api_key" / "oauth2_client_secret" / "bootstrap_token" / "bearer_token" / "basic_auth" / tstr

; Certificate encoding formats
CertFormat = "pem" / "der"

; Private key encoding formats  
KeyFormat = "pkcs1" / "pkcs8"
```

**For password type:**

```cddl
PasswordCredential = {
    username: tstr,             ; Username for authentication
    password: tstr,             ; Password (hashed or plaintext)
    ? hash_algorithm: HashAlgorithm,  ; bcrypt, pbkdf2, scrypt, argon2
    ? scope: tstr,               ; Usage scope (e.g., "sudoers", "api.example.com")
    ? expires_at: tstr           ; ISO 8601 expiration timestamp
}
```

**For unified secret type (api_key, oauth2, jwt, bearer_token):**

```cddl
SecretCredential = {
    ? client_id: tstr,           ; Client identifier (optional)
    secret: tstr,                ; Opaque secret string
    ? type: SecretType,          ; api_key, oauth2_client_secret, bootstrap_token, bearer_token, basic_auth
    ? endpoint: tstr              ; Service endpoint URL (optional)
}
```

The `type` field is a hint for the client application and is opaque to the FDO protocol. The values listed below are **suggested** common types, but implementations may use any string value that makes sense for their use case.

**Suggested type values:**

- `api_key` - Static, long-lived string used directly in headers
- `oauth2_client_secret` - Permanent secret for Client Credentials flow
- `bootstrap_token` - One-time-use ticket for initial registration
- `bearer_token` - Pre-generated access token for Authorization header
- `basic_auth` - Legacy username:password pair (client_id is username)

**Note:** Implementations are free to define additional secret types as needed for their specific requirements.

**Note:** The FDO protocol treats the `secret` as an opaque string. The `type` and `endpoint` fields are provided for client convenience only.

### Example: Provisioned Credentials - Unified Secret

```
Owner → Device:
fdo.credentials:credential-begin = {
    0: 156,
    1: -16,                    ; SHA-256
    -1: "api-access-key",
    -2: "secret",
    -4: "https://api.example.com/v1"
}

Owner → Device:
fdo.credentials:credential-data-0 = <CBOR bstr containing SecretCredential: {"client_id": "device-001", "secret": "sk_live_abc123...", "type": "api_key", "endpoint": "https://api.example.com/v1"}>

Owner → Device:
fdo.credentials:credential-end = {
    0: 0,
    1: h'a3b5c7...'
}

Device → Owner:
fdo.credentials:credential-result = [0, "API key stored"]
```

## Enrolled Credentials Flow

### Use Cases

- X.509 certificate enrollment (CSR-based)
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
    ? 1: hash_alg: int           ; COSE hash algorithm identifier
    -1: credential_id: tstr      ; e.g., "device-mtls-cert"
    -2: credential_type: CredentialType  ; 3=x509_cert, 4=server_generated_key (for enrolled)
    ? -4: endpoint_url: tstr     ; Service endpoint URL where credential is used
}
```

### Request Data Format

**For x509_cert type:**

```cddl
X509CertRequest = {
    csr: tstr                    ; PEM-encoded PKCS#10 Certificate Signing Request
}
```

- CSR in PKCS#10 format (DER or PEM encoded)
- Device has generated key pair, CSR contains subject DN, SAN, key usage

### response-begin Message

```cddl
{
    0: total_size: uint
    ? 1: hash_alg: int           ; COSE hash algorithm identifier
    -1: credential_id: tstr
    -2: credential_type: CredentialType  ; 3=x509_cert, 4=server_generated_key (for enrolled)
    ? -4: endpoint_url: tstr     ; Service endpoint URL where credential is used (server-specified)
}
```

### Response Data Format

**For x509_cert type:**

```cddl
X509CertResponse = {
    certificate: tstr,          ; PEM or DER encoded X.509 certificate
    ? ca_bundle: [ * tstr ],     ; Array of CA certificates (optional)
    ? cert_format: CertFormat    ; pem, der
}
```

- Signed X.509 certificate (DER or PEM)
- Optionally followed by CA bundle (concatenated certificates)

### Example: Enrolled Credentials - X.509 Certificate

```
Device → Owner:
fdo.credentials:request-begin = {
    0: 1024,
    1: -16,                    ; SHA-256
    -1: "device-mtls-cert",
    -2: "x509_cert"
}

Device → Owner:
fdo.credentials:request-data-0 = <CBOR bstr containing X509CertRequest: {"csr": "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----"}>

Device → Owner:
fdo.credentials:request-end = {
    0: 0,
    1: h'csr-hash...'
}

Owner → Device:
fdo.credentials:response-begin = {
    0: 2048,
    1: -16,                    ; SHA-256
    -1: "device-mtls-cert",
    -2: "x509_cert",
    -4: "https://api.example.com/v1"
}

Owner → Device:
fdo.credentials:response-data-0 = <CBOR bstr containing X509CertResponse: {"certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----", "ca_bundle": ["-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"], "cert_format": "pem"}>

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
    -2: credential_type: CredentialType  ; 5=ssh_public_key (for registered)
    ? -4: endpoint_url: tstr     ; Service endpoint URL where public key will be used
}
```

### pubkey-begin Message

```cddl
{
    0: total_size: uint
    ? 1: hash_alg: int           ; COSE hash algorithm identifier
    -1: credential_id: tstr      ; e.g., "device-mgmt-key"
    -2: credential_type: tstr    ; "ssh_public_key"
    ? -4: endpoint_url: tstr     ; Service endpoint URL where public key will be used
}
```

### Public Key Data Format

**For ssh_public_key type:**

```cddl
SSHPublicKey = {
    -1: public_key: tstr,       ; OpenSSH or RFC 4716 format public key
    ? -2: username: tstr,          ; Username account for SSH access
    ? -3: key_type: tstr,         ; rsa, ed25519, ecdsa, dsa
    ? -4: comment: tstr           ; Key comment/description
}
```

- SSH public key in OpenSSH format (e.g., "ssh-rsa AAAAB3NzaC1...")
- Or SSH public key in RFC 4716 format

**Note on username field:**

The optional `username` field in the payload specifies which user account the SSH key should be associated with. This is useful when:

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
    -4: "ssh://config-server.example.com:22"
}

Device → Owner:
fdo.credentials:pubkey-begin = {
    0: 68,
    1: -16,                    ; SHA-256
    -1: "device-config-access",
    -2: 5                      ; ssh_public_key
}

Device → Owner:
fdo.credentials:pubkey-data-0 = <CBOR bstr containing SSHPublicKey: {"public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGbVQa6Y8bPQc4yYj+nUEhCgM+jhGQsCCLXX/XrX6q7o", "username": "admin", "key_type": "ed25519", "comment": "device-001 config access key"}>

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
    -4: "https://api.example.com/v1"
}

Owner → Device: fdo.credentials:credential-data-0 = <CBOR bstr: {"api_key": "sk_live_abc123...", "service": "api.example.com", "scope": "read write", "expires_at": "2027-01-01T00:00:00Z"}>

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
    -2: "x509_cert"
}

Device → Owner: fdo.credentials:request-data-0 = <CBOR bstr: {"csr": "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----"}>

Device → Owner: fdo.credentials:request-end = {0: 0, 1: h'csr-hash...'}

# Owner returns certificate + CA bundle
Owner → Device: fdo.credentials:response-begin = {
    0: 3072,
    1: "sha256",
    -1: "mtls-identity",
    -2: "x509_cert",
    -4: "https://api.example.com/v1"
}

Owner → Device: fdo.credentials:response-data-0 = <CBOR bstr: {"certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----", "ca_bundle": ["-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"], "cert_format": "pem"}>

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
    -2: "ssh_public_key"
}

Device → Owner: fdo.credentials:pubkey-data-0 = <CBOR bstr: {"public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...", "username": "admin", "authorized_hosts": ["server1.example.com"], "key_type": "ed25519"}>

Device → Owner: fdo.credentials:pubkey-end = {0: 0, 1: h'pubkey-hash...'}

Owner → Device: fdo.credentials:pubkey-result = [0, "Public key added to authorized_keys on server1.example.com"]

# Device deactivates module
Device → Owner: fdo.credentials:active = false
```

---

**End of Specification**
