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

#### Revocation for Offline/Dark Sites

Standard revocation methods (CRL/OCSP) require internet connectivity to certificate authorities. For devices operating in:

- **Dark sites** (air-gapped networks)
- **Offline environments** (limited or no internet access)
- **Remote locations** (intermittent connectivity)

Additional revocation strategies may be warranted:

- **Local CRL distribution**: Periodically download and cache CRLs during connectivity windows
- **Push-based revocation**: Use out-of-band channels (e.g., satellite, cellular) to push revocation lists
- **Short-lived certificates**: Use very short validity periods (hours/days) to minimize exposure
- **Device-specific revocation lists**: Maintain device-local revocation status updated during maintenance windows
- **Multi-factor validation**: Require additional verification when connectivity is unavailable

**Note**: Attested Payload (also known as "Offline FDO") is a prime example where traditional network-based certificate revocation mechanisms cannot be relied upon. In these cases, alternative revocation strategies become critical for maintaining security.

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
- Consider additional revocation strategies for offline/dark sites (local CRL caching, push-based revocation, short-lived certs)
- Add certificate transparency logging
- Regularly rotate certificates and private keys
- **Consider limiting delegate certificate chain depth**: The library does not enforce a maximum depth for delegate certificate chains. Production deployments should consider implementing a reasonable limit (e.g., 10-20 certificates) to prevent potential DoS attacks through excessively deep chains. The appropriate limit depends on your delegation hierarchy requirements.

### Key Management

- Store private keys securely (TPM, HSM, or encrypted storage)
- Use cryptographically secure random serial numbers
- Consider longer validity periods with proper revocation
- Ensure proper entropy sources for random number generation

### Operational Security

- Enable security-relevant logging and monitoring
- Monitor for failed authentication attempts and certificate validation failures

### Rendezvous Service Security

The Rendezvous (RV) service acts as a directory service that maps device GUIDs to owner connection information. Proper security controls are critical to prevent denial-of-service attacks and unauthorized voucher registration.

#### AcceptVoucher Callback (REQUIRED for Production)

**⚠️ CRITICAL**: Production deployments **MUST** implement the `AcceptVoucher` callback to control which vouchers are accepted by the RV service.

Without this callback, the RV service will accept vouchers from any entity that can construct a valid voucher chain, potentially allowing:

- Unauthorized entities to register vouchers
- Malicious actors to overwrite legitimate device registrations
- Denial-of-service attacks by flooding the RV service with vouchers

**Example implementation:**

```go
rvServer := &fdo.TO0Server{
    Session: state,
    RVBlobs: state,
    AcceptVoucher: func(ctx context.Context, ov fdo.Voucher, requestedTTL uint32) (uint32, error) {
        // Verify the voucher owner is authorized
        ownerKey, err := ov.OwnerPublicKey()
        if err != nil {
            return 0, fmt.Errorf("invalid voucher owner key: %w", err)
        }
        
        // Check against authorized owner list
        if !isAuthorizedOwner(ownerKey) {
            return 0, fmt.Errorf("unauthorized owner")
        }
        
        // Optionally enforce TTL limits
        maxTTL := uint32(86400) // 24 hours
        if requestedTTL > maxTTL {
            return maxTTL, nil
        }
        
        return requestedTTL, nil
    },
}
```

**Authorization strategies:**

- **Allowlist of owner public keys**: Maintain a list of authorized owner keys
- **Certificate-based authorization**: Verify owner certificates against trusted CAs
- **API key/token validation**: Require authentication tokens for TO0 operations
- **Rate limiting**: Limit voucher registrations per owner/IP address
- **Audit logging**: Log all voucher registration attempts for security monitoring

#### GUID Collision and Voucher Replacement Policies

##### Security Issue

Device GUIDs are 128-bit random values. While collision probability is negligible in normal operation (~10^-18 at current IoT scale), a malicious manufacturer could deliberately create a device with the same GUID as an existing device to cause a denial-of-service attack:

1. Manufacturer A creates Device A with GUID X
2. Owner A registers GUID X at the RV service
3. Malicious Manufacturer B deliberately creates Device B with the same GUID X
4. Malicious Owner B registers GUID X, potentially **overwriting** Owner A's registration
5. Device A may no longer be able to onboard (depending on voucher validation)

There are several potential ways in which a real-world implmentation MAY handle such scenarios. The best one for any deployment depends on the specifics of that real-world use-case

##### Option 0: No Restriction (Current Default)

By default, the RV service allows any valid voucher to replace an existing GUID registration, regardless of manufacturer or owner. This provides maximum operational flexibility but minimal protection against malicious replacement.

Tradeoffs:

- ✅ Maximum operational flexibility
- ✅ Allows any legitimate corrections (lost keys, address changes, ownership transfers)
- ❌ **No protection against malicious GUID collision attacks**
- ❌ Requires external authorization controls (via `AcceptVoucher` callback)

##### Configurable Protection Policies

The RV service supports configurable policies to control GUID replacement behavior. The example server provides a `-rv-replacement-policy` flag to select the policy:

```bash
# Use manufacturer key consistency (recommended)
go run ./examples/cmd server -rv-replacement-policy manufacturer-key-consistency

# Or use numeric value
go run ./examples/cmd server -rv-replacement-policy 1
```

##### Option 1: Manufacturer Key Consistency (Recommended)

Enforce that voucher replacements for the same GUID must be signed by the same manufacturer.

Implementation approach:

```go
// Enforced automatically by TO0Server when VoucherReplacementPolicy is set:
// 1. Retrieve existing voucher for GUID (if any)
// 2. Compare manufacturer public key hash
// 3. Reject if manufacturer key differs
```

Tradeoffs:

- ✅ Prevents cross-manufacturer GUID collision attacks
- ✅ Allows legitimate owner key rotation (same manufacturer, different owner)
- ✅ Allows service address updates
- ✅ Allows ownership transfers within same manufacturer
- ❌ Requires manufacturer key to remain constant
- ❌ Cannot recover if manufacturer key is lost/compromised

##### Option 2: First-Registration Lock (High Security)

Lock the GUID to the first registered voucher until expiration. Only allow replacement after the TTL expires.

Implementation approach:

```go
// Enforced automatically by TO0Server when VoucherReplacementPolicy is set:
// 1. Check if GUID exists and is not expired
// 2. Reject any replacement attempt before expiration
```

Tradeoffs:

- ✅ Maximum protection against replacement attacks during validity period
- ✅ Prevents all unauthorized overwrites
- ✅ Simple to implement and reason about
- ❌ **Blocks ALL corrections** (lost owner keys, address changes, ownership transfers)
- ❌ Problematic for devices with long shelf life (months/years before onboarding)
- ❌ Requires manual intervention or waiting for expiration for legitimate changes
- ❌ May require short TTLs (limiting DoS window) vs. operational needs (long shelf life)

##### Option 3: Owner Key Consistency (Alternative)

Enforce that replacements must be signed by the same owner (final entry in voucher chain).

Implementation approach:

```go
// Enforced automatically by TO0Server when VoucherReplacementPolicy is set:
// 1. Retrieve existing voucher for GUID
// 2. Extract owner public key from final voucher entry
// 3. Compare with new voucher's owner key
// 4. Reject if owner key differs
```

Tradeoffs:

- ✅ Allows manufacturer key rotation
- ✅ Allows service address updates by same owner
- ❌ Prevents legitimate ownership transfers
- ❌ More complex to implement (owner key is at end of voucher chain)
- ❌ Cannot recover if owner key is lost/compromised

##### Deployment Recommendations

For most production deployments:

1. **Choose Option 1 (Manufacturer Key Consistency)** as the replacement policy for best balance of security and operational flexibility
2. **Implement monitoring and alerting** for GUID replacement attempts, especially with key mismatches
3. **Provide administrative override mechanism** for legitimate recovery scenarios

For high-security environments where devices have short time-to-onboard:

- Consider **Option 2 (First-Registration Lock)** with appropriately short TTLs
- **Note**: Option 2 requires the RV operator to provide out-of-band support for legitimate voucher replacement requests (e.g., lost owner keys, address changes). Owners should be able to contact the RV operator through a manual process to request voucher updates when the automated protocol blocks legitimate corrections.

For environments with complex supply chains:

- Consider **Option 3 (Owner Key Consistency)** if manufacturer key rotation is required
- **Note**: Option 3 also requires out-of-band support for ownership transfer scenarios. The RV operator should provide a manual process for authorized ownership changes that cannot be handled through the automated protocol.

##### Additional Safeguards

- **Monitoring**: Alert on GUID replacement attempts, especially with manufacturer/owner key mismatches
- **Rate limiting**: Limit TO0 operations per GUID/IP address to prevent rapid replacement attacks
- **Audit logging**: Log all voucher registrations with manufacturer/owner key fingerprints, timestamps, and source IPs
- **Manual override**: Provide administrative interface for legitimate GUID recovery scenarios
- **TTL management**: Balance security (short TTLs limit attack window) vs. operations (long shelf life)

## Protocol Security Features

### Attested Payload ("Offline FDO")

Attested Payload is used in scenarios where devices are offline or not responding to the network. It enables:

- Local users to perform authorized operations (installation, diagnostics, recovery)
- Proof of authorization for specific operations without network connectivity
- Owner-authorized work to be performed offline with cryptographic verification

This is particularly valuable for:

- Emergency maintenance or recovery
- Diagnostic operations in air-gapped environments
- Field service operations without network access

### Anti-DoS Protection

- FDO 2.0 includes anti-DoS protection where the device proves itself first before the owner proves ownership. This prevents resource exhaustion attacks on the owner service.

### Version Negotiation

- Version negotiation via capability flags prevents downgrade attacks

### Message Authentication

- All protocol messages are authenticated using HMAC

---

**IMPORTANT**: This is not an exhaustive security guide. Consult with security professionals for your specific deployment requirements and conduct regular security assessments.
