# Enhanced Certificate Validation Error Reporting

## Overview

This enhancement provides detailed certificate validation error reporting to help onboarding services diagnose and resolve certificate issues during FDO device onboarding.

## Problem Solved

Previously, when certificate validation failed (expired certificates, revoked certificates, etc.), the client received only generic error messages like "delegate chain verification failed" with no specific information about what went wrong. This made it difficult for operators to diagnose and fix certificate issues.

## Solution Components

### 1. CertificateValidationError Types

New `CertificateValidationErrorCode` enum provides specific error categories:

- `CertValidationErrorExpired` - Certificate has expired
- `CertValidationErrorNotYetValid` - Certificate not yet valid (NotBefore in future)
- `CertValidationErrorRevoked` - Certificate revoked (via custom checker)
- `CertValidationErrorCustomCheck` - Custom certificate validation failed
- `CertValidationErrorSignature` - Certificate signature verification failed
- `CertValidationErrorKeyUsage` - Certificate lacks required key usage
- `CertValidationErrorBasicConstraints` - Certificate basic constraints invalid
- `CertValidationErrorMissingPermission` - Certificate missing required FDO permission
- `CertValidationErrorNotCA` - Intermediate certificate is not a CA
- `CertValidationErrorChainHashMismatch` - Certificate chain hash mismatch

### 2. EnhancedCertificateChecker Interface

New interface that provides detailed error information:

```go
type EnhancedCertificateChecker interface {
    CheckCertificate(cert *x509.Certificate) *CertificateValidationError
}
```

### 3. Backward Compatibility

Legacy `CertificateChecker` implementations are automatically wrapped and their errors converted to appropriate `CertificateValidationError` types.

### 4. Detailed Error Messages

Errors now include:

- **Specific error code** (e.g., "certificate expired")
- **Certificate subject** (e.g., "CN=device-123")
- **Context** (e.g., "delegate chain", "certificate chain")
- **Detailed message** (e.g., "expired (NotAfter: 2024-01-15)")

## Implementation Details

### Error Flow

1. **Certificate Validation**: During delegate chain or OV certificate validation
2. **Error Creation**: Specific `CertificateValidationError` created with details
3. **Protocol Conversion**: Error converted to FDO `ErrorMessage` for client
4. **Client Receives**: Detailed error string with specific failure reason

### Example Error Messages

**Before**:

```terminal
"delegate chain verification failed"
```

**After**:

```terminal
"Certificate validation failed: certificate expired (subject: CN=device-123)"
```

### Coverage Areas

The enhanced validation applies to:

1. **Delegate Certificates**: Server-provided delegate certificate chains
2. **OV Device Certificates**: Certificate chains in Ownership Voucher extensions  
3. **OV Manufacturer Certificates**: Manufacturer certificate chains in vouchers
4. **OV Owner Certificates**: Owner certificate chains in voucher entries

## Usage Examples

### Enhanced Certificate Checker

```go
type EnhancedOCSPChecker struct{}

func (e *EnhancedOCSPChecker) CheckCertificate(cert *x509.Certificate) *CertificateValidationError {
    // Check OCSP
    if revoked, err := checkOCSP(cert); err != nil {
        return NewCertificateValidationError(
            CertValidationErrorCustomCheck,
            cert,
            "OCSP verification", 
            fmt.Sprintf("OCSP check failed: %v", err),
        )
    } else if revoked {
        return NewCertificateValidationError(
            CertValidationErrorRevoked,
            cert,
            "OCSP verification",
            "certificate revoked via OCSP",
        )
    }
    return nil
}
```

### Legacy Certificate Checker (Automatically Wrapped)

```go
type LegacyRevocationChecker struct{}

func (l *LegacyRevocationChecker) CheckCertificate(cert *x509.Certificate) error {
    if time.Now().After(cert.NotAfter) {
        return fmt.Errorf("certificate expired")
    }
    return nil
}
```

## Security Considerations

### Information Disclosure

The solution provides certificate subject information and specific validation failure reasons. This is **secure** because:

1. **Server already has certificates** - No new information is disclosed
2. **Failure reasons only** - Success/failure status is already known
3. **No private keys** - Only public certificate information is shared
4. **Operator benefit** - Helps diagnose legitimate configuration issues

### Error Message Content

Error messages include:

- ✅ **Certificate subject** (public information)
- ✅ **Validation failure reason** (helpful for debugging)
- ✅ **Context** (where validation occurred)
- ❌ **Private keys** (never included)
- ❌ **Internal system details** (not exposed)

## Migration Guide

### For Existing Users

No changes required - existing `CertificateChecker` implementations continue to work and are automatically enhanced.

### For New Implementations

Implement `EnhancedCertificateChecker` for detailed error reporting:

```go
func SetCertificateChecker(checker interface{}) {
    // Can accept either CertificateChecker or EnhancedCertificateChecker
    // Enhanced checkers provide detailed error information
}
```

## Testing

The implementation includes:

1. **Unit tests** for all error types
2. **Integration tests** for delegate chain validation
3. **Backward compatibility tests** for legacy checkers
4. **Error message format tests**

## Benefits

1. **Faster Troubleshooting**: Operators can quickly identify certificate issues
2. **Better Monitoring**: Enhanced logging with specific error types
3. **Reduced Support Tickets**: Clear error messages reduce confusion
4. **Improved Security**: Easier to identify and fix certificate configuration issues
5. **Backward Compatibility**: No breaking changes for existing deployments

## Files Modified

- `cert_validation_errors.go` - New error types and interfaces
- `delegate.go` - Enhanced delegate certificate validation
- `voucher.go` - Enhanced OV certificate validation  
- `to2.go` - Enhanced error reporting to clients
- `examples/enhanced_cert_validation.go` - Usage examples

## Future Enhancements

Potential future improvements:

1. **Certificate-specific error codes** in protocol specification
2. **Structured error reporting** with machine-readable error details
3. **Certificate telemetry** for monitoring certificate health
4. **Automated remediation suggestions** based on error types
