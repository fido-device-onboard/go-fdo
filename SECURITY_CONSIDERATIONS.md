# Security Considerations for Production Deployments

This document outlines specific security concerns and recommendations for using the go-fdo library in production environments.

## Potential Security Concerns

### Certificate Generation for Testing Only

**⚠️ IMPORTANT**: The certificate generation code in this library is intended **ONLY for testing and development purposes**. It uses simplified practices that are NOT suitable for production deployments.

For production use, certificates should be:
- Created by external Certificate Authorities (CAs) or third-party services
- Signed by externally-managed Hardware Security Modules (HSMs)
- Generated using proper PKI practices and enterprise certificate management systems

### No Revocation Checking by Default

The library warns: "No CertificateChecker configured - revocation checking (CRL/OCSP) is disabled"

- **Risk**: This could allow use of revoked certificates
- **Mitigation**: Use the `SetCertificateChecker()` API to implement custom validation

```go
type OCSPChecker struct{}

func (c *OCSPChecker) CheckCertificate(cert *x509.Certificate) error {
    // Implement OCSP checking here
    // Return error if certificate is revoked
    return nil
}

// Configure at application startup
fdo.SetCertificateChecker(&OCSPChecker{})
```

### Test-Only Certificate Practices

The following issues are present in the test certificate generation code:

#### Weak Certificate Validity Period
```go
NotAfter: time.Now().Add(30 * 24 * time.Hour), // Only 30 days
```
- **Purpose**: Super-short validity limits exposure during testing
- **Production**: Use appropriate validity periods (typically 1-3 years) with proper revocation

#### Deterministic Serial Numbers
```go
SerialNumber: big.NewInt(1), // Leaf
SerialNumber: big.NewInt(2), // Parent
```
- **Purpose**: Predictable serial numbers simplify test debugging
- **Production**: Use cryptographically secure random serial numbers to prevent attacks

#### No Certificate Transparency Logging
- **Purpose**: CT logging unnecessary for test certificates
- **Production**: Implement certificate transparency logging for detecting misissued certificates

#### Simplified Random Number Generation
- **Purpose**: Basic `rand.Reader` sufficient for test environments
- **Production**: Ensure proper entropy sources and validated random number generation

## 🔒 Production Recommendations

### Certificate Management
- Use external Certificate Authorities (CAs) or third-party certificate services
- Sign certificates with externally-managed Hardware Security Modules (HSMs)
- Implement proper PKI practices and enterprise certificate management systems
- **Always configure CertificateChecker with CRL/OCSP validation**
- Add certificate transparency logging
- Regularly rotate certificates and private keys

### Key Management
- Store private keys securely (TPM, HSM, or encrypted storage)
- Use cryptographically secure random serial numbers
- Consider longer validity periods with proper revocation
- Ensure proper entropy sources for random number generation

### Operational Security
- Enable security-relevant logging and monitoring
- Monitor for failed authentication attempts and certificate validation failures

## Protocol Security Features

- FDO 2.0 includes anti-DoS protection where the device proves itself first
- Version negotiation via capability flags prevents downgrade attacks
- All protocol messages are authenticated using HMAC

---

**IMPORTANT**: This is not an exhaustive security guide. Consult with security professionals for your specific deployment requirements and conduct regular security assessments.