# Delegate Certificate Validation

This document describes how delegate certificate chains are validated in the FDO library and how to configure custom certificate checking for production deployments.

## What is Validated

When a delegate certificate chain is validated, the following checks are performed:

| Check | Status | Description |
| ----- | ------ | ----------- |
| Signature chain | ✅ Implemented | Each certificate is verified to be signed by its issuer |
| Expiration | ✅ Implemented | `NotBefore` and `NotAfter` are checked against current time |
| Key usage | ✅ Implemented | Digital signature and cert signing permissions are verified |
| FDO permissions (OIDs) | ✅ Implemented | Custom FDO permission OIDs are validated |
| Basic constraints | ✅ Implemented | CA flag and constraints are verified |
| Revocation (CRL/OCSP) | ⚠️ **Not implemented** | Requires custom `CertificateChecker` |

## Revocation Checking

**The reference implementation does NOT check certificate revocation (CRL/OCSP).**

Go's standard `crypto/x509` library does not provide built-in revocation checking. Implementing CRL or OCSP requires:

- Network calls to fetch revocation data
- Infrastructure-specific configuration
- Caching and performance considerations

For production deployments, you **should** implement revocation checking using the `CertificateChecker` interface.

## CertificateChecker Interface

The library provides an extensibility hook for custom certificate validation:

```go
type CertificateChecker interface {
    // CheckCertificate performs custom validation on a certificate.
    // It is called for each certificate in the delegate chain during validation.
    // Return nil if the certificate is valid, or an error to reject it.
    CheckCertificate(cert *x509.Certificate) error
}
```

### Setting a Custom Checker

Call `SetCertificateChecker()` once at application startup:

```go
package main

import (
    "crypto/x509"
    fdo "github.com/fido-device-onboard/go-fdo"
)

type MyRevocationChecker struct {
    // Add fields for OCSP responder URLs, CRL cache, etc.
}

func (c *MyRevocationChecker) CheckCertificate(cert *x509.Certificate) error {
    // Example: Check OCSP
    if len(cert.OCSPServer) > 0 {
        // Implement OCSP checking using golang.org/x/crypto/ocsp
        // ...
    }
    
    // Example: Check CRL
    if len(cert.CRLDistributionPoints) > 0 {
        // Fetch and check CRL
        // ...
    }
    
    return nil // Certificate is valid
}

func main() {
    // Set the checker at startup
    fdo.SetCertificateChecker(&MyRevocationChecker{})
    
    // ... rest of application
}
```

### Warning Messages

If no `CertificateChecker` is configured, the library will log a warning for each certificate validated:

```text
WARN: No CertificateChecker configured - revocation checking (CRL/OCSP) is disabled
  cert_subject: CN=myDelegate_ec384_1
  hint: Call fdo.SetCertificateChecker() to enable custom certificate validation
```

**These warnings are expected during development and testing.** They serve as a reminder that production deployments should implement proper revocation checking.

## Example CRL Checker

Here's an example of CRL-based revocation checking:

```go
import (
    "crypto/x509"
    "fmt"
    "io"
    "net/http"
    "sync"
    "time"
)

type CRLChecker struct {
    HTTPClient *http.Client
    cache      map[string]*x509.RevocationList
    cacheMu    sync.RWMutex
}

func (c *CRLChecker) CheckCertificate(cert *x509.Certificate) error {
    if len(cert.CRLDistributionPoints) == 0 {
        // No CRL distribution point - skip or fail based on policy
        return nil
    }
    
    for _, crlURL := range cert.CRLDistributionPoints {
        crl, err := c.fetchCRL(crlURL)
        if err != nil {
            continue // Try next distribution point
        }
        
        // Check if certificate is in the revoked list
        for _, revoked := range crl.RevokedCertificateEntries {
            if revoked.SerialNumber.Cmp(cert.SerialNumber) == 0 {
                return fmt.Errorf("certificate %s is revoked (serial: %s)", 
                    cert.Subject, cert.SerialNumber)
            }
        }
    }
    
    return nil
}

func (c *CRLChecker) fetchCRL(url string) (*x509.RevocationList, error) {
    // Check cache first (implementation omitted for brevity)
    
    resp, err := c.HTTPClient.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    crlBytes, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    
    return x509.ParseRevocationList(crlBytes)
}
```

## Example OCSP Checker

Here's an example using Go's `golang.org/x/crypto/ocsp` package.

Note: OCSP requires the issuer certificate to create a request. In a delegate chain, the issuer is the next certificate in the chain (e.g., `chain[i+1]` is the issuer of `chain[i]`).

```go
import (
    "bytes"
    "crypto/x509"
    "fmt"
    "io"
    "net/http"
    
    "golang.org/x/crypto/ocsp"
)

type OCSPChecker struct {
    HTTPClient *http.Client
    // The delegate chain being validated - needed to find issuer certs
    Chain      []*x509.Certificate
}

func (c *OCSPChecker) CheckCertificate(cert *x509.Certificate) error {
    if len(cert.OCSPServer) == 0 {
        // No OCSP server specified - skip check or return error based on policy
        return nil
    }
    
    // Find the issuer certificate in the chain
    issuer := c.findIssuer(cert)
    if issuer == nil {
        // No issuer found - this is the root, skip OCSP
        return nil
    }
    
    for _, ocspURL := range cert.OCSPServer {
        ocspReq, err := ocsp.CreateRequest(cert, issuer, nil)
        if err != nil {
            continue
        }
        
        resp, err := c.HTTPClient.Post(ocspURL, "application/ocsp-request", 
            bytes.NewReader(ocspReq))
        if err != nil {
            continue
        }
        defer resp.Body.Close()
        
        respBytes, err := io.ReadAll(resp.Body)
        if err != nil {
            continue
        }
        
        ocspResp, err := ocsp.ParseResponse(respBytes, issuer)
        if err != nil {
            continue
        }
        
        if ocspResp.Status == ocsp.Revoked {
            return fmt.Errorf("certificate %s is revoked", cert.Subject)
        }
        
        return nil // Successfully verified
    }
    
    return nil // No OCSP server responded, policy decision needed
}

func (c *OCSPChecker) findIssuer(cert *x509.Certificate) *x509.Certificate {
    for i, chainCert := range c.Chain {
        if chainCert.Equal(cert) && i+1 < len(c.Chain) {
            return c.Chain[i+1]
        }
    }
    return nil
}
```

## Dark-Site and Offline Environments

A critical consideration for FDO deployments is that **delegate certificate validation typically occurs on devices**, and devices may be:

- **Offline** during onboarding
- **In a dark-site** (air-gapped network) with no external connectivity
- **Behind firewalls** that block access to public OCSP responders or CRL distribution points

This creates a fundamental challenge: even if a device can communicate with an onboarding service on a local network, it may be unable to reach the OCSP or CRL servers specified in the delegate certificates.

### Implications for Revocation Checking

Standard revocation mechanisms assume network connectivity to external servers. In dark-site deployments, this assumption breaks down entirely. Possible approaches include:

1. **Proxy revocation data through the onboarding service** - The onboarding service fetches and caches CRL/OCSP responses, then provides them to devices as part of the onboarding flow.

2. **Pre-staged revocation data** - CRLs are periodically exported and deployed to the dark-site network, where devices can access them from a local server.

3. **Signed revocation attestations** - The onboarding service provides signed statements about certificate validity that devices can verify, rather than contacting the original OCSP/CRL servers.

4. **Short-lived delegate certificates** - Use certificates with very short validity periods (hours or days) instead of relying on revocation, accepting the operational overhead of frequent renewal.

5. **Skip revocation entirely** - Accept the security trade-off in environments where revocation infrastructure is impractical, relying on other controls (physical security, network isolation, etc.).

### Why This Is Left as a Callback

The `CertificateChecker` interface is intentionally minimal and flexible because:

- **No single approach fits all deployments** - A cloud-connected factory has very different constraints than an air-gapped military installation.

- **Non-standard handling may be required** - Implementations might need to trust revocation data from the onboarding service rather than the servers listed in certificates, which is outside the scope of standard X.509 validation.

- **Policy decisions are deployment-specific** - Whether to fail-open or fail-closed when revocation data is unavailable depends on the security requirements of each environment.

The reference implementation provides the hook; production deployments must implement the policy appropriate to their environment.

## Security Considerations

1. **Production deployments SHOULD implement revocation checking where feasible** - Without it, compromised or revoked delegate certificates could still be accepted. However, recognize that standard revocation may not be possible in all environments.

2. **Cache revocation data appropriately** - OCSP and CRL responses can be cached to reduce latency and network load. In dark-site environments, cached data may be the only option.

3. **Handle network failures gracefully** - Decide whether to fail-open or fail-closed when revocation servers are unreachable. Document this decision as part of your security policy.

4. **Consider the threat model** - In a physically secured dark-site, the risk of a compromised delegate certificate may be lower than in a cloud-connected environment. Adjust revocation requirements accordingly.

5. **Consider OCSP stapling or similar mechanisms** - Where the onboarding service can reach external networks, it may be able to provide stapled OCSP responses to offline devices.
