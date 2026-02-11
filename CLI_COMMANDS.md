# FDO CLI Commands Reference

This document provides comprehensive documentation for all FDO (FIDO Device Onboard) command-line tools and their usage.

## Overview

The FDO CLI provides four main commands:

- `client` - Device-side operations (DI, TO1, TO2, voucher management)
- `server` - Owner-side operations (DI server, TO2 server, rendezvous)
- `delegate` - Delegate certificate management
- `attestpayload` - Attested payload creation and verification

## Client Commands

### Basic Usage

```bash
go run ./cmd client [flags]
```

### Device Initialization (DI)

**Purpose:** Establishes trust between device and manufacturer by creating an ownership voucher. This is the first step in the FDO protocol where the device gets its unique identity and credentials. DI runs against a manufacturing server and creates a `creds.blob` file containing device information that must be secured in the device's Root of Trust (RoE) - this file is required for all subsequent onboarding operations.

```bash
# Perform DI against manufacturing server
go run ./cmd client -di http://manufacturer.example.com:9999

# DI with specific key type (used in manufacturing for different device capabilities)
go run ./cmd client -di http://manufacturer.example.com:9999 -di-key rsa2048

# DI with custom device info encoding (x509, x5chain, cose)
go run ./cmd client -di http://manufacturer.example.com:9999 -di-key-enc x509
```

**Real-world context:** Used in manufacturing environments where devices are first initialized. The test suite shows this as the foundational step before any onboarding can occur. The resulting `creds.blob` contains the device's ownership voucher and cryptographic material that must be protected.

### Transfer of Ownership (TO1/TO2)

**Purpose:** Transfers device ownership from manufacturer to the actual owner. TO1 finds the owner via rendezvous service, TO2 establishes secure channel and configures the device. **Requires device has undergone DI first.**

```bash
# Complete TO1/TO2 process (standard onboarding)
go run ./cmd client

# TO1 only (rendezvous lookup, used in distributed deployments)
go run ./cmd client -rv-only

# TO2 with specific FDO version (for protocol compatibility)
go run ./cmd client -fdo-version 200

# TO2 with single-sided attestation (WiFi-only mode, no owner verification)
go run ./cmd client -allow-single-sided
```

**Single-sided attestation:** Used for WiFi-only onboarding by untrusted manufacturing services. In this mode, the device doesn't verify the owner's identity, allowing onboarding in scenarios where the owner cannot be fully authenticated (e.g., public WiFi hotspots, untrusted manufacturing environments). This should only be used when full owner verification is not possible.

**Real-world context:** The test suite demonstrates different scenarios:

- Basic TO1/TO2 for standard onboarding
- FDO 2.0 protocol for newer devices
- Credential reuse for multiple onboarding cycles
- Single-sided mode for WiFi-only setups

### Voucher Management

#### List Vouchers

```bash
# List all vouchers in database
go run ./cmd client -list-vouchers -db fdo.db

# Output:
Vouchers in database fdo.db:
==================================================
GUID: 3737643032663038366133306164636332346233613539386638643738366166
  Device Info: gotest
  Created: 1970-01-01T00:29:30Z

Total: 1 voucher(s)
```

#### Export Vouchers

```bash
# Export most recent voucher to stdout (PEM format)
go run ./cmd client -voucher-export - -db fdo.db

# Export to file
go run ./cmd client -voucher-export voucher.pem -db fdo.db

# Export specific voucher by GUID
go run ./cmd client -voucher-export - -db fdo.db -voucher-guid 3737643032663038366133306164636332346233613539386638643738366166

# Export by serial number (searches device_info)
go run ./cmd client -voucher-export - -db fdo.db -voucher-serial gotest

# Export in JSON format
go run ./cmd client -voucher-export - -db fdo.db -voucher-format json

# Export in raw CBOR format
go run ./cmd client -voucher-export - -db fdo.db -voucher-format cbor
```

#### Export Formats

**PEM Format (Default):**

```
-----BEGIN OWNERSHIP VOUCHER-----
hRhlWPKGGGVQd9AvCGowrcwks6WY+NeGr4KBgg1BAIOCDEEBggJRUAAAAAAAAAAAAAD//38AAAGC

...
-----END OWNERSHIP VOUCHER-----

```

**JSON Format:**

```json
{
  "guid": "3737643032663038366133306164636332346233613539386638643738366166",
  "device_info": "gotest",
  "manufacturer_key": {
    "type": 11
  },
  "rv_info": [...],
  "entries_count": 1
}
```

### Device Configuration

**Purpose:** Configure device-specific settings and access methods.

```bash
# Print device credential blob (for debugging and verification)
go run ./cmd client -print

# Use TPM for hardware-backed device secrets (enhanced security)
go run ./cmd client -tpm /dev/tpm0

# Specify custom credential blob file (for testing or manual credential management)
# Default: uses creds.blob created during DI
go run ./cmd client -blob custom-cred.bin
```

### Service Info Modules (FSIM) - Device Configuration

**Purpose:** Specify system configuration data that will be sent via applicable FSIMs upon device onboarding. These are generic device provisioning data that devices receive at onboarding time.

#### Device Configuration FSIMs

**Purpose:** Configure device-specific settings and services during onboarding.

```bash
# Configure supported BMO (Boot Management Overlay) MIME types for firmware updates
go run ./cmd client -bmo-supported-types application/x-iso9660-image,application/octet-stream

# Configure supported payload MIME types for data transfer
go run ./cmd client -payload-supported-types application/json,text/plain
```

#### Data Transfer FSIMs

**Purpose:** Manage file transfers and command execution between device and owner.

```bash
# Upload files to owner (for device data collection or backup)
go run ./cmd client -upload /path/to/file1,/path/to/file2

# Download files from owner (for configuration updates or software distribution)
go run ./cmd client -download /path/to/download


# Execute commands on device (for remote management)
go run ./cmd client -echo-commands

# wget files from URLs (for software updates or data retrieval)
go run ./cmd client -wget-dir /downloads
```

**Real-world context:** The test suite demonstrates various FSIM scenarios:

- **Payload FSIM:** File transfer for firmware and configuration
- **BMO FSIM:** Boot image management for device updates
- **Sysconfig FSIM:** System configuration (hostname, timezone, NTP)
- **WiFi FSIM:** Network configuration for wireless devices
- **Credentials FSIM:** SSH key registration and CSR enrollment

### Credential Management (FSIM)

**Purpose:** Manage device credentials during onboarding, including SSH keys and certificate enrollment for secure device access. This is part of device configuration via the Credentials FSIM.

```bash
# Register SSH public key with owner (for secure remote access)
go run ./cmd client -register-ssh-key device-ssh-key:ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDevicePublicKeyExample

# Enroll CSR for certificate-based authentication (used in PKI environments)
go run ./cmd client -enroll-csr device-mtls-cert:-----BEGIN CERTIFICATE REQUEST-----...-----END CERTIFICATE REQUEST-----
```

**Real-world context:** The test suite shows these being used for:

- SSH key registration for device remote access
- CSR enrollment for certificate-based authentication
- Integration with enterprise PKI systems

### Cryptographic Configuration

**Purpose:** Configure cryptographic algorithms and security parameters for the FDO protocol.

```bash
# Specify cipher suite for encryption (data protection)
go run ./cmd client -cipher A256GCM

# Specify key exchange suite (secure channel establishment)
go run ./cmd client -kex ASYMKEX2048

# Skip TLS certificate verification (testing environments only)
go run ./cmd client -insecure-tls
```

**Real-world context:** The test suite shows:

- RSA2048 keys for encryption scenarios
- ASYMKEX2048 for key exchange testing
- Different cipher suites for compatibility testing

## Server Commands

### Basic Usage

```bash
go run ./cmd server [flags]
```

### Server Configuration

**Purpose:** Configure and start the FDO owner server that handles device initialization and onboarding requests.

```bash
# Basic server setup (development/testing)
go run ./cmd server -http "127.0.0.1:9999" -db fdo.db

# Production server with owner certificates (for manufacturing environments)
go run ./cmd server -http "0.0.0.0:9999" -db fdo.db -owner-certs

# Server with TLS for secure communication
go run ./cmd server -http "127.0.0.1:9999" -db fdo.db -insecure-tls

# Server with external address (for cloud deployments)
go run ./cmd server -http "0.0.0.0:9999" -db fdo.db -ext-http "fdo.example.com:9999"
```

**Real-world context:** The test suite uses various server configurations:

- Basic servers for simple testing
- Owner certificates for manufacturing environments
- TLS for secure communication testing
- External addresses for distributed deployments

### Database Configuration

**Purpose:** Manage the FDO database that stores vouchers, keys, and device information.

```bash
# Server with encrypted database (production security)
go run ./cmd server -db fdo.db -db-pass "strong-password"

# Initialize database only (setup phase)
go run ./cmd server -initOnly -db fdo.db
```

**Real-world context:** Used for:

- Database setup during initial deployment
- Security configuration for production environments
- Database maintenance and backup procedures

### Service Info Modules (FSIM) - Server Configuration

**Purpose:** Configure server-side services that devices can access during onboarding. These specify the system configuration data that will be sent to devices.

#### Device Configuration FSIMs

**Purpose:** Configure device-specific settings during onboarding.

```bash
# Payload FSIM - Distribute files to devices (firmware, configuration)
go run ./cmd server -payload application/json:config.json -payload application/octet-stream:firmware.bin

# BMO FSIM - Boot image management for device updates
go run ./cmd server -bmo application/x-iso9660-image:boot.iso

# WiFi Configuration FSIM - Configure wireless network settings
go run ./cmd server -wifi-config wifi-config.json

# System Configuration FSIM - Set device system parameters
go run ./cmd server -sysconfig hostname=test-device -sysconfig timezone=UTC -sysconfig ntp-server=pool.ntp.org
```

#### Credential Management FSIM

**Purpose:** Manage device credentials and authentication during onboarding.

```bash
# Provision credentials to devices (passwords, API keys, OAuth tokens)
go run ./cmd server -credential password:admin-creds:admin:SecurePass123:https://mgmt.example.com/api \
  -credential api_key:prod-api:sk_live_abc123xyz:https://api.example.com/v1 \
  -credential oauth2_client_secret:oauth-app:client_secret_xyz789:https://oauth.example.com/token

# Request SSH public key from devices (for secure access)
go run ./cmd server -request-pubkey ssh_public_key:device-ssh-key:ssh://admin.example.com:22
```

**Real-world context:** Used in enterprise environments for:

- Automated device provisioning with various credential types
- SSH key management for secure remote access

- Integration with enterprise authentication systems

#### Data Transfer FSIMs

**Purpose:** Manage file transfers and command execution.

```bash
# Command FSIM - Execute commands on devices for remote management
go run ./cmd server -command-date

# Download FSIM - Collect files from devices
go run ./cmd server -download /path/to/file1 -download /path/to/file2

# Upload FSIM - Receive files from devices (logs, diagnostics)
go run ./cmd server -upload-dir /uploads
```

**Real-world context:** The test suite demonstrates comprehensive FSIM usage:

- **Payload transfer** for firmware and configuration distribution
- **BMO** for boot image management and OTA updates
- **Sysconfig** for device initialization parameters
- **WiFi** for network configuration
- **Credentials** for secure device access

### Rendezvous Configuration

**Purpose:** Configure rendezvous service for device-to-owner discovery in distributed deployments.

```bash
# Use external rendezvous server (distributed manufacturing)
go run ./cmd server -to0 http://rendezvous.example.com:9999

# Register specific device GUID immediately (bypass normal discovery)
go run ./cmd server -to0 http://rendezvous.example.com:9999 -to0-guid 3737643032663038366133306164636332346233613539386638643738366166

# Skip TO1 (direct TO2 for known devices)
go run ./cmd server -rv-bypass

# Delay TO1 (staggered device registration)
go run ./cmd server -rv-delay 30

# Configure RV voucher replacement policy (security controls)
go run ./cmd server -rv-replacement-policy manufacturer-key-consistency
```

**Real-world context:** Used in large-scale deployments for:

- Distributed manufacturing with separate rendezvous infrastructure
- Load balancing and device registration management
- Security policy enforcement for voucher replacement

### Delegate Configuration

**Purpose:** Configure delegate certificates for supply chain operations and multi-owner scenarios. See [delegate.md](delegate.md) for comprehensive delegate documentation.

```bash
# Use delegate for TO2 operations (supply chain handoffs)
go run ./cmd server -onboardDelegate myDelegate

# Use delegate for RV blob signing (delegated manufacturing)
go run ./cmd server -rvDelegate myDelegate
```

**Real-world context:** The test suite demonstrates delegate usage for:

- Multi-owner device handoffs in manufacturing
- Delegated manufacturing scenarios
- Complex ownership transfer workflows

### Voucher Management

**Purpose:** Import and extend ownership vouchers for various operational scenarios.

```bash
# Import voucher from PEM file (manual voucher management)
go run ./cmd server -import-voucher voucher.pem

# Extend voucher for resale (device resale scenarios)
go run ./cmd server -resale-guid 3737643032663038366133306164636332346233613539386638643738366166 \
  -resale-key next-owner.pub

# Print owner certificate chain (for verification and debugging)
go run ./cmd server -print-owner-chain ec384

# Print owner private key (for testing and development only)
go run ./cmd server -print-owner-private ec384

# Print owner public key (for certificate validation)
go run ./cmd server -print-owner-public ec384
```

**Real-world context:** Used for:

- Manual voucher management in edge cases
- Device resale and second-owner scenarios
- Supply chain voucher operations
- Certificate chain verification
- Debugging cryptographic operations
- Key rotation and management procedures

## Delegate Commands

### Basic Usage

```bash
go run ./cmd delegate [flags]
```

### Delegate Operations

**Purpose:** Create and manage delegate certificates for supply chain operations and multi-owner scenarios. See [delegate.md](delegate.md) for comprehensive delegate documentation.

```bash
# Create delegate chain for TO2 operations (supply chain handoff)
go run ./cmd delegate -db fdo.db create myDelegate onboard,redirect SECP384R1 ec384

# Create delegate for credential provisioning
go run ./cmd delegate -db fdo.db create provisionDelegate provision SECP384R1 ec384

# Print delegate chain for verification
go run ./cmd delegate -db fdo.db -print-delegate-chain ec384

# Print delegate private key (for testing only)
go run ./cmd delegate -db fdo.db -print-delegate-private ec384
```

**Real-world context:** The test suite shows delegate usage for:

- Multi-owner device handoffs in manufacturing
- Delegated credential provisioning
- Complex supply chain operations with multiple stakeholders

### Delegate Types

- `onboard,redirect` - For TO2 operations (device to first owner)
- `provision` - For credential provisioning services
- `resale` - For device resale scenarios

### Key Types

- `ec256` - ECDSA P-256 (smaller key size, faster operations)
- `ec384` - ECDSA P-384 (recommended for production)
- `rsa2048` - RSA 2048-bit (legacy compatibility)
- `rsa3072` - RSA 3072-bit (higher security)

## Attested Payload Commands

### Basic Usage

```bash
go run ./cmd attespayload [flags]
```

### Create Attested Payload

**Purpose:** Create and verify cryptographically signed data packages that can be verified to have been created by a specific device with a valid voucher. See [attestedpayload.md](attestedpayload.md) for comprehensive attested payload documentation.

```bash
# Create with text payload (simple secure data transfer)
go run ./cmd attestpayload -db fdo.db -voucher voucher.pem -payload "Hello World" -output payload.fdo

# Create with file payload (firmware, configuration, logs)
go run ./cmd attestpayload -db fdo.db -voucher voucher.pem -file data.bin -output payload.fdo

# Create with MIME type (for structured data)
go run ./cmd attestpayload -db fdo.db -voucher voucher.pem -payload "config.json" -type "application/json" -output payload.fdo

# Create with delegate signing (supply chain verification)
go run ./cmd attestpayload -db fdo.db -voucher voucher.pem -delegate myDelegate -payload "Secure Data" -output payload.fdo

# Create encrypted payload (RSA device keys required)
go run ./cmd attestpayload -db fdo.db -voucher voucher.pem -payload "Secret Data" -encrypt -output encrypted.fdo

# Create with expiration (time-limited data)
go run ./cmd attestpayload -db fdo.db -voucher voucher.pem -payload "Time-limited Data" -expires "2025-12-31T23:59:59Z" -output payload.fdo

# Create with generation number (versioning and supersession)
go run ./cmd attestpayload -db fdo.db -voucher voucher.pem -payload "Config v2" -id "network-config" -gen 2 -output payload.fdo
```

**Real-world context:** The test suite shows attested payload usage for:

- Secure data transfer between device and owner
- Firmware and configuration distribution with cryptographic verification
- Delegate-signed payloads for supply chain verification
- Encrypted payloads for sensitive data protection
- Time-limited data for temporary configurations

### Database Configuration

```bash
# Use encrypted database (production security)
go run ./cmd attestpayload -db fdo.db -db-pass "password" -voucher voucher.pem -payload "Data"
```

## Global Options

### Debug Mode

**Purpose:** Enable verbose logging and debugging information for troubleshooting.

```bash
# Enable debug output for any command
go run ./cmd client -debug -di http://manufacturer.example.com:9999
go run ./cmd server -debug -http "127.0.0.1:9999" -db fdo.db
```

### Help

**Purpose:** Get help information for commands and options.

```bash
# Get help for main command
go run ./cmd --help

# Get help for specific subcommand
go run ./cmd client --help
go run ./cmd server --help
go run ./cmd delegate --help
go run ./cmd attestpayload --help
```

## Troubleshooting

### Common Errors and Solutions

**Database not found:**

```bash
Error: database file not found: fdo.db
Solution: Ensure database file exists or create it with -initOnly
```

**Invalid GUID format:**

```bash
Error: invalid GUID format
Solution: Use 32-character hex string (e.g., 3737643032663038366133306164636332346233613539386638643738366166)
```

**No voucher found:**

```bash
Error: no voucher found matching criteria
Solution: Check GUID/serial number or use -list-vouchers to see available vouchers
```

**Connection refused:**

```bash
Error: connection refused
Solution: Ensure server is running and accessible on specified port
```

## Tips and Best Practices

### Database Management

- Always specify database path with `-db` flag
- Use `-initOnly` to create new databases
- Back up databases before major operations
- Use encrypted databases in production with `-db-pass`

### Voucher Management

- Use `-list-vouchers` to see available vouchers before export
- Export vouchers in PEM format for long-term storage
- Use JSON format for programmatic processing
- Search by serial number when GUID is unknown

### Security

- Use TLS in production environments
- Protect database files with appropriate permissions
- Use certificate validation (`-insecure-tls` only for testing)
- Rotate delegate certificates regularly

### Performance

- Use appropriate key sizes (EC384 recommended)
- Limit concurrent connections to prevent overload
- Monitor database size and perform maintenance
- Use debug mode sparingly in production

## Integration Examples

### Shell Scripts

```bash
#!/bin/bash
# Automated device onboarding script

DB_FILE="production.db"
SERVER_URL="https://fdo.manufacturer.com:9999"

# 1. Check existing vouchers
echo "Checking existing vouchers..."
go run ./cmd client -list-vouchers -db "$DB_FILE"

# 2. Perform DI
echo "Performing device initialization..."
go run ./cmd client -di "$SERVER_URL"

# 3. Export voucher for records
echo "Exporting voucher..."
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
go run ./cmd client -voucher-export "voucher_${TIMESTAMP}.pem" -db "$DB_FILE"

echo "Device onboarding completed successfully!"
```

This documentation provides a comprehensive reference for all FDO CLI commands, making it easy for users to find the right commands and options for their specific use cases, with real-world examples from the test suite.
