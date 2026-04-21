# FDO Service Info Modules (FSIMs) Overview

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

## Quick Summary

| FSIM | Primary Purpose | Key Characteristics | Typical Use Cases |
| --- | --- | --- | --- |
| **fdo.payload** | Generic data delivery based on MIME type | Type-centric processing, multi-platform support, content-driven | Shell scripts, cloud-init, configs, firmware updates |
| **fdo.sysconfig** | Fundamental OS configuration | Cross-platform, essential settings, standardized primitives | Hostname, timezone, DNS, basic security policies |
| **fdo.csr** | Certificate management for mutual TLS | PKI integration, day-2 operations, mutual authentication | Client certificates, CA distribution, certificate renewal |
| **fdo.wifi** | Wi-Fi network access configuration | Authentication flexibility, trust levels, attestation compatibility | Password auth, enterprise Wi-Fi, onboarding networks |

## Overview

FDO Service Info Modules (FSIMs) are specialized protocol extensions that enable targeted device configuration during the onboarding process. Each FSIM addresses a specific configuration domain with appropriate complexity, security considerations, and operational semantics. This document provides a high-level overview of the primary FSIMs and their intended use cases.

## FSIM Summary

### fdo.payload - Generic Data Delivery

**High-Level Intent**: Deliver arbitrary data types to devices for processing based on MIME type identification.

**Key Characteristics**:

- **Content-Type Driven**: Uses MIME types to identify data format and processing requirements
- **Multi-Platform Support**: Different endpoint systems may understand different MIME types
- **Processing-Oriented**: Focuses on what the device should DO with the data, not just where to store it

**Comparison to fdo.upload**:

- **fdo.upload**: File-centric - "put this file at this location"
- **fdo.payload**: Type-centric - "here's data of type X, process it appropriately"

**Use Cases**:

- Shell scripts for system configuration
- Cloud-init configuration files
- Ansible playbooks or other infrastructure-as-code
- JSON/YAML configuration data
- Binary firmware updates
- Container manifests

**Design Philosophy**: The payload FSIM treats data as having semantic meaning through its MIME type, allowing diverse devices to interpret and apply the same data in ways appropriate to their capabilities and operating environment.

---

### fdo.sysconfig - Fundamental System Configuration

**High-Level Intent**: Provide an extensible, general-purpose mechanism for bare-metal onboarded systems to receive fundamental OS-level configuration.

**Key Characteristics**:

- **OS-Agnostic**: Works across different operating systems and platforms
- **Core Configuration**: Focuses on essential settings any provisioned system typically needs
- **Extensible Design**: Can accommodate new configuration domains as needs evolve

**Fundamental Configuration Domains**:

- **Identity**: Hostname, device identification
- **Time**: Timezone, NTP configuration
- **Network**: Basic network settings (DNS, search domains)
- **Security**: Basic security policies

**Design Philosophy**: Sysconfig addresses the "table stakes" configuration that virtually every provisioned system requires, regardless of its specific role or application. It provides a baseline that enables devices to participate in managed environments.

**Why Not Use Payload?**: While payload could deliver this data, sysconfig provides standardized, well-defined configuration primitives that don't require MIME type negotiation or custom processing logic on the device side.

---

### fdo.csr - Certificate Management for Mutual TLS

**High-Level Intent**: Enable client and management systems to establish mutual TLS authentication required for day-2 operations.

**Key Characteristics**:

- **Security-Focused**: Establishes trust relationships for ongoing management
- **Mutual Authentication**: Both client and server sides require certificates
- **PKI Integration**: Interfaces with existing certificate authorities and PKI infrastructure

**Certificate Operations**:

- **Client Certificate Enrollment**: Device obtains identity certificates
- **CA Certificate Distribution**: Devices receive trust anchors
- **Server-Side Key Generation**: For devices that cannot generate their own keys
- **Re-enrollment**: Certificate renewal and rotation

**Day-2 Operations Focus**: CSR FSIM is specifically designed for establishing the long-term security relationships needed beyond initial onboarding. These certificates enable secure management, monitoring, and operational interactions throughout the device lifecycle.

**Why Separate FSIM?**: Certificate management involves complex security considerations, PKI integration, and specific protocol requirements (RFC 7030/EST) that warrant dedicated handling rather than being embedded in a generic data delivery mechanism.

---

### fdo.wifi - Network Access Configuration

**High-Level Intent**: Configure Wi-Fi network access with support for both simple and complex authentication scenarios.

**Key Characteristics**:

- **Authentication Flexibility**: Supports both password-based and certificate-based authentication
- **Trust Level Differentiation**: Can configure networks for onboarding-only or full operational use
- **Attestation Compatibility**: Works in both fully attested and restricted/delegate permission scenarios

**Configuration Complexity**:

- **Simple Setup**: WPA2-PSK/WPA3-PSK with shared passwords
- **Complex Setup**: WPA3-Enterprise with certificate authentication
- **Certificate Exchange**: CSR/certificate provisioning for enterprise networks

**Trust Management**:

- **Onboard-Only Networks**: Temporary access for initial provisioning
- **Full-Access Networks**: Long-term operational network access
- **Owner-Declared Trust**: Network trustworthiness based on Owner's assessment

**Why Dedicated FSIM?**: Wi-Fi configuration involves unique complexities that justify specialized handling:

1. **Authentication Complexity**: Ranges from simple passwords to enterprise certificate exchanges
2. **Trust Semantics**: Different networks serve different purposes (onboarding vs. operations)
3. **Attestation Flexibility**: May be permitted even in restricted attestation scenarios
4. **Security Requirements**: Certificate provisioning and network security policies

**Special Considerations**: Wi-Fi setup is unique among FSIMs because it may be the critical first step that enables all other onboarding activities. A device cannot receive other configuration if it cannot first connect to a network.

---

## FSIM Design Philosophy

### Domain Separation

Each FSIM addresses a specific configuration domain with appropriate complexity:

- **Single Responsibility**: Each FSIM has a clear, focused purpose
- **Appropriate Complexity**: Complexity matches the problem domain requirements
- **Clear Boundaries**: Minimal overlap between FSIM responsibilities

### Security Considerations

FSIMs are designed with different security postures:

- **fdo.wifi**: May work in restricted attestation scenarios
- **fdo.csr**: Requires full attestation for certificate operations
- **fdo.sysconfig**: Basic configuration with standard security
- **fdo.payload**: Security depends on MIME type and processing requirements

### Extensibility

The FSIM architecture allows for:

- **New Modules**: Additional FSIMs for new configuration domains
- **Protocol Evolution**: Existing FSIMs can be enhanced over time
- **Vendor Extensions**: Custom FSIMs for specialized requirements

## Implementation Guidance

### Choosing the Right FSIM

**Use fdo.payload when**:

- Delivering custom data formats
- Processing logic varies by device type
- MIME type negotiation is appropriate
- Data interpretation is device-specific

**Use fdo.sysconfig when**:

- Configuring basic OS parameters
- Standardized configuration primitives are needed
- Cross-platform compatibility is required
- Core system settings are being established

**Use fdo.csr when**:

- Establishing mutual TLS relationships
- Long-term security credentials are needed
- PKI integration is required
- Day-2 operations will use certificate-based auth

**Use fdo.wifi when**:

- Configuring network access (Wi-Fi)
- Both simple and complex authentication are needed
- Trust level differentiation is required
- Onboarding scenarios may have restricted attestation

### FSIM Interaction Patterns

FSIMs are typically used in combination during onboarding:

1. **Network First**: fdo.wifi (if needed) to establish connectivity
2. **Security Next**: fdo.csr to establish trust relationships
3. **Basic Config**: fdo.sysconfig for fundamental system settings
4. **Application Config**: fdo.payload for application-specific configuration

## Conclusion

FDO FSIMs provide a modular, extensible framework for device onboarding that balances simplicity with flexibility. Each FSIM addresses specific configuration needs with appropriate complexity, security considerations, and operational semantics. This modular approach enables:

- **Clear Separation of Concerns**: Each FSIM has a focused purpose
- **Appropriate Complexity**: Complexity matches the problem domain
- **Security Posture Alignment**: Different FSIMs for different security requirements
- **Extensibility**: Room for growth and specialization

The FSIM architecture ensures that devices can be onboarded efficiently while maintaining the flexibility to handle diverse deployment scenarios and requirements.
