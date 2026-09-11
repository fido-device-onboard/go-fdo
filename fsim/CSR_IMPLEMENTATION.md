# fdo.csr FSIM Implementation Guide

Copyright &copy; 2026 Dell Technologies and FIDO Alliance

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

This document describes the implementation of the `fdo.csr` FSIM (Certificate Signing Request module) for FDO certificate enrollment.

## Overview

The `fdo.csr` FSIM enables secure certificate enrollment during FDO device onboarding. It allows devices to:

1. Obtain CA certificates from the Onboarding Service (OBS)
2. Generate private keys and create Certificate Signing Requests (CSRs)
3. Receive signed certificates from the OBS

The implementation follows the specification in `fdo.csr.md` and uses RFC 7030 (EST) standard formats.

## Basic Certificate Enrollment Flow

| Step | What Happens | Device Sends | Owner Sends | FSIM Key Name |
| ---- | ------------ | ------------ | ----------- | ------------- |
| **1. Get CA Bundle** | Endpoint requests CA certificates from OBS | `fdo.csr:cacerts-req` | - | `cacerts-req` |
| | OBS returns CA certificate(s) | - | `fdo.csr:cacerts-res` | `cacerts-res` |
| **2. Create Key & CSR** | Endpoint generates private key locally | (internal operation) | - | - |
| | Endpoint creates CSR with public key | - | - | - |
| | Endpoint sends CSR to OBS | `fdo.csr:simpleenroll-req` | - | `simpleenroll-req` |
| **3. Sign & Return Cert** | OBS validates and signs CSR | - | (internal operation) | - |
| | OBS returns signed certificate | - | `fdo.csr:simpleenroll-res` | `simpleenroll-res` |

## Message Format Details

| FSIM Key | Direction | Value Type | Content |
| -------- | --------- | ---------- | ------- |
| `fdo.csr:cacerts-req` | Device → Owner | `uint` | Format code (281=PKCS#7, 287=single cert) |
| `fdo.csr:cacerts-res` | Owner → Device | `tstr` | Base64-encoded CA certificate(s) |
| `fdo.csr:simpleenroll-req` | Device → Owner | `tstr` | Base64-encoded PKCS#10 CSR |
| `fdo.csr:simpleenroll-res` | Owner → Device | `tstr` | Base64-encoded X.509 certificate |

## Additional Operations

| Operation | Request Key | Response Key | Purpose |
| --------- | ----------- | ------------ | ------- |
| Re-enrollment | `fdo.csr:simplereenroll-req` | `fdo.csr:simplereenroll-res` | Renew/rekey existing cert |
| Server keygen | `fdo.csr:serverkeygen-req` | `fdo.csr:serverkeygen-res` | OBS generates key for device |
| CSR attributes | `fdo.csr:csrattrs-req` | `fdo.csr:csrattrs-res` | Get required CSR fields |
| Error | - | `fdo.csr:error` | Error code (1-5) |

## Implementation Files

- **`csr_device.go`** - Device-side CSR module implementation
- **`csr_owner.go`** - Owner-side CSR module implementation

## Device-Side Usage

### Basic Enrollment

    import (
        "crypto/ecdsa"
        "crypto/elliptic"
        "crypto/rand"
        "crypto/x509/pkix"
        "github.com/fido-device-onboard/go-fdo/fsim"
    )
    
    // Create CSR module
    csrModule := &fsim.CSR{
        // Key generation function
        GenerateKey: func() (crypto.Signer, error) {
            return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
        },
        
        // Certificate subject
        Subject: pkix.Name{
            CommonName:   "device-12345",
            Organization: []string{"Example Corp"},
        },
        
        // Certificate installation callback
        InstallCertificate: func(cert *x509.Certificate) error {
            // Store certificate (e.g., to file, TPM, etc.)
            return saveCertificate(cert)
        },
        
        // CA certificate installation callback
        InstallCACerts: func(certs []*x509.Certificate) error {
            // Update trust anchors
            return updateTrustStore(certs)
        },
    }
    
    // Register module
    deviceModules := map[string]serviceinfo.DeviceModule{
        "fdo.csr": csrModule,
    }
    
    // During TO2, the module will:
    // 1. Request CA certs: csrModule.RequestCACerts(ctx, 281, respond, yield)
    // 2. Enroll: csrModule.Enroll(ctx, respond, yield)

### Re-enrollment (Certificate Renewal)

    csrModule := &fsim.CSR{
        GenerateKey: keyGenFunc,
        Subject:     subject,
        
        // For re-enrollment, provide existing cert and key
        ExistingCert: currentCertificate,
        ExistingKey:  currentPrivateKey,
        
        InstallCertificate: installFunc,
    }
    
    // This will use simplereenroll instead of simpleenroll
    csrModule.Enroll(ctx, respond, yield)

### Server-Side Key Generation

For constrained devices that cannot generate keys:

    csrModule := &fsim.CSR{
        // Don't set GenerateKey - this triggers server-side keygen
        GenerateKey: nil,
        
        Subject: subject,
        
        // Install both certificate and private key
        InstallCertificate: installCertFunc,
        InstallPrivateKey: func(key crypto.PrivateKey) error {
            // Securely store private key
            return savePrivateKey(key)
        },
    }

## Owner-Side Usage

### Basic Setup with CA Integration

    import (
        "github.com/fido-device-onboard/go-fdo/fsim"
    )
    
    // Create CSR owner module
    csrOwner := &fsim.CSROwner{
        // CA certificates to distribute to devices
        CACerts: []*x509.Certificate{rootCA, intermediateCA},
        
        // Enrollment handler - integrates with your CA
        HandleEnrollment: func(ctx context.Context, csrDER []byte) (*x509.Certificate, error) {
            // Parse CSR
            csr, err := x509.ParseCertificateRequest(csrDER)
            if err != nil {
                return nil, err
            }
            
            // Send to CA for signing (e.g., via EST, ACME, or direct CA API)
            cert, err := yourCA.SignCSR(csr)
            if err != nil {
                return nil, err
            }
            
            return cert, nil
        },
        
        // Optional: Re-enrollment handler
        HandleReenrollment: func(ctx context.Context, csrDER []byte, existingCert *x509.Certificate) (*x509.Certificate, error) {
            // Similar to enrollment but may have different policies
            return yourCA.RenewCertificate(csrDER, existingCert)
        },
    }
    
    // Register module
    ownerModules := map[string]serviceinfo.OwnerModule{
        "fdo.csr": csrOwner,
    }

### Self-Signed Certificates (Testing Only)

For testing purposes, a self-signed enrollment handler is provided:

    // Generate a signing key
    signingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

    csrOwner := &fsim.CSROwner{
        CACerts: []*x509.Certificate{selfSignedCA},
        
        // Use built-in self-signed handler (NOT for production!)
        HandleEnrollment: fsim.SelfSignedEnrollmentHandler(signingKey),
    }

⚠️ **Warning**: Self-signed certificates should only be used for testing. Production deployments must integrate with a proper CA/RA.

### Server-Side Key Generation

    csrOwner := &fsim.CSROwner{
        CACerts: caCerts,
        
        HandleServerKeygen: func(ctx context.Context, csrDER []byte) (*x509.Certificate, crypto.PrivateKey, error) {
            // Parse CSR for subject info (public key is ignored)
            csr, _ := x509.ParseCertificateRequest(csrDER)
            
            // Generate private key
            key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
            if err != nil {
                return nil, nil, err
            }
            
            // Create and sign certificate
            cert, err := yourCA.IssueCertificate(csr.Subject, key.Public())
            if err != nil {
                return nil, nil, err
            }
            
            return cert, key, nil
        },
    }

## Error Codes

The `fdo.csr:error` message uses the following error codes:

| Error Code | Description | Sent in response to |
| ---------- | ----------- | ------------------- |
| 1 | Bad request | Any malformed request |
| 2 | Unauthorized | Enrollment/re-enrollment denied |
| 3 | Feature not supported | Optional feature not implemented |
| 4 | Rate exceeded. Try later | Too many requests |
| 5 | Unsupported format | Invalid format in cacerts-req |

## Security Considerations

### Device Side

1. **Private Key Protection**: Private keys should never leave the device
   - Store in TPM, secure enclave, or encrypted storage
   - Use hardware key generation when available

2. **CA Certificate Validation**: Verify CA certificates before installation
   - Check certificate validity periods
   - Verify certificate chains
   - Consider pinning expected CA public keys

3. **CSR Integrity**: CSR signature provides proof-of-possession
   - Device signs CSR with its private key
   - Owner validates signature before issuing certificate

### Owner Side

1. **CSR Validation**: Always validate CSRs before signing
   - Verify CSR signature (proof-of-possession)
   - Check subject fields against policy
   - Validate public key parameters

2. **Authorization**: Implement proper authorization checks
   - Verify device identity before enrollment
   - Check enrollment policies (rate limits, allowed subjects, etc.)
   - Log all enrollment attempts

3. **CA Integration**: Secure communication with CA/RA
   - Use mutual TLS for CA connections
   - Validate CA responses
   - Handle CA errors appropriately

4. **Server-Side Key Generation**: Extra care required
   - Private keys must be transmitted securely (FDO provides channel security)
   - Consider additional encryption for private keys
   - Ensure keys are generated with proper entropy

## Integration with EST (RFC 7030)

The `fdo.csr` FSIM uses EST-compatible message formats, making it easy to integrate with existing EST infrastructure:

- **CA Certificates**: Uses `application/pkcs7-mime` or `application/pkix-cert`
- **CSRs**: Uses `application/pkcs10` (PKCS#10 format)
- **Certificates**: Uses `application/pkix-cert` (DER-encoded X.509)
- **Server Keygen**: Uses `multipart/mixed` with `application/pkcs8` and `application/pkcs7-mime`

The owner-side module can act as an EST proxy, forwarding requests to an EST server and translating responses back to the device.

## Production Deployment Checklist

### Device Side

- [ ] Implement secure key generation (TPM, secure enclave, etc.)
- [ ] Implement secure certificate storage
- [ ] Implement CA certificate validation
- [ ] Configure appropriate certificate subject fields
- [ ] Test enrollment and re-enrollment flows
- [ ] Implement error handling and retry logic

### Owner Side

- [ ] Integrate with production CA/RA
- [ ] Implement authorization and policy checks
- [ ] Configure rate limiting
- [ ] Set up audit logging
- [ ] Test with various CSR formats
- [ ] Implement monitoring and alerting
- [ ] Document CA integration procedures

## Troubleshooting

### Common Issues

#### Device receives error code 1 (Bad request)

- Check CSR format is valid PKCS#10
- Verify base64 encoding is correct
- Ensure CSR signature is valid

#### Device receives error code 2 (Unauthorized)

- Check device authorization with owner
- Verify enrollment policies allow this device
- Check rate limits haven't been exceeded

#### Device receives error code 3 (Feature not supported)

- Owner doesn't support requested operation (e.g., server-side keygen)
- Fall back to supported features

#### Certificate installation fails

- Verify certificate matches CSR public key
- Check certificate validity period
- Ensure certificate chain is complete

## References

- **Specification**: `fdo.csr.md` - Full FSIM specification
- **RFC 7030**: Enrollment over Secure Transport (EST)
- **RFC 2986**: PKCS #10 - Certification Request Syntax
- **RFC 5280**: X.509 Certificate and CRL Profile
