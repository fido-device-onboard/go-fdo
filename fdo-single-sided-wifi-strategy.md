# Single-Sided FDO Client Strategy for Wi-Fi Onboarding

## Overview

This document outlines the strategy and implementation plan for creating a single-sided FDO client that enables Wi-Fi onboarding without full Owner attestation. The approach allows devices to obtain Wi-Fi credentials while maintaining security boundaries.

## Problem Statement

Traditional FDO requires full Owner attestation to complete the TO2 protocol. However, for Wi-Fi onboarding scenarios, devices need to:

1. Connect to a network to reach the real Owner service
2. Obtain Wi-Fi credentials without full Owner verification
3. Maintain security boundaries to prevent information leakage

## Solution Strategy

### Core Concept

Create a **single-sided FDO client mode** that:

- Performs device attestation (device proves legitimacy)
- Skips Owner verification (service doesn't prove ownership)
- Allows only Wi-Fi credential provisioning
- Blocks all other FSIM operations

### Security Approach

#### Single-Sided Profile

When a device detects it has undergone single-sided attestation (device proved legitimacy, but owner was not verified), it MUST enter a **single-sided profile** with the following constraints:

##### 1. FSIM Restrictions

Only `devmod` and `fdo.wifi` FSIMs are available:

```text
Single-Sided Profile - Available FSIMs:
├── devmod       ✅ (minimal data only - see below)
├── fdo.wifi     ✅ (untrusted networks only - see below)
├── fdo.bmo      ❌ BLOCKED
├── fdo.payload  ❌ BLOCKED
├── fdo.sysconfig ❌ BLOCKED
└── fdo.credentials ❌ BLOCKED
```

The device MUST NOT advertise other FSIMs in `devmod:modules` and MUST reject attempts by the server to use blocked FSIMs.

##### 2. Minimal devmod Data

The device SHOULD report only the fields necessary for FSIM discovery:

```text
REQUIRED (for FSIM discovery):
- devmod:active = true
- devmod:nummodules = 1  
- devmod:modules = [0, 0, "fdo.wifi"]
- devmod:sep = ";"

OMIT OR EMPTY (identifying information):
- devmod:device = ""
- devmod:serial = ""  (CRITICAL: never expose serial to untrusted owner)
- devmod:os = ""
- devmod:version = ""
- devmod:arch = ""
```

This protects device identity from untrusted owner services while remaining FDO-compliant.

##### 3. Trust Level Enforcement

**Critical**: The device MUST treat ALL received networks as **untrusted** (`trust_level = 0`), regardless of what the server specifies:

```text
Server sends:  trust_level = 1 (full-access)
Device applies: trust_level = 0 (onboard-only)
```

This is **not an error condition**. The server MAY believe the network is trusted (from its perspective), but the device cannot verify this claim without owner attestation. The device:

- SHOULD silently downgrade `trust_level` to 0
- SHOULD NOT reject the network or report an error
- MUST use the network only for further onboarding, not for general connectivity

#### Full Owner Profile

When a device undergoes full owner/delegate attestation (mutual verification), all restrictions are lifted:

```text
Full Owner Profile - Available FSIMs:
├── devmod        ✅ (full data)
├── fdo.wifi      ✅ (trusted networks allowed)
├── fdo.bmo       ✅
├── fdo.payload   ✅
├── fdo.sysconfig ✅
└── fdo.credentials ✅
```

- **Complete devmod**: Report all applicable fields including serial numbers
- **Trust levels honored**: Networks can be marked as `full-access` for general connectivity
- **All FSIMs available**: BMO, payloads, credentials, etc.

#### Service Deployment Models

##### WiFi-Only Service (Single-Sided)

For operators who want to provide Wi-Fi hints without requiring trust:

- Deploy single-sided attestation service
- Expect clients to provide minimal devmod data
- Expect clients to downgrade all trust levels
- Do NOT attempt to use BMO, payload, or other FSIMs

##### Full Onboarding Service (Full Owner)

For operators providing complete device provisioning:

- Deploy full owner/delegate attestation service
- Expect clients to provide complete devmod data
- Trust levels will be honored as specified
- All FSIMs available based on client capabilities

## Implementation Plan

### Phase 1: Protocol Layer Changes

#### 1.1 Single-Sided Mode Detection

Add logic to detect single-sided mode:

```go
// In TO2 protocol handler
type OnboardingMode int

const (
    ModeUnknown OnboardingMode = iota
    ModeSingleSided
    ModeDoubleSided
)

func DetermineMode(ownerVerified bool, serviceType string) OnboardingMode {
    if !ownerVerified && serviceType == "wifi-setup" {
        return ModeSingleSided
    }
    if ownerVerified {
        return ModeDoubleSided
    }
    return ModeUnknown
}
```

#### 1.2 Owner Verification Bypass

Modify TO2 protocol to:

- Skip Owner Key verification in single-sided mode
- Continue with device attestation only
- Maintain cryptographic verification of device identity

#### 1.3 Mode State Management

Add mode tracking to device state:

```go
type DeviceState struct {
    // Existing fields...
    OnboardingMode OnboardingMode
    OwnerVerified  bool
    ServiceType    string
}
```

### Phase 2: FSIM Layer Changes

#### 2.1 Use Existing fdo.wifi FSIM

The existing `fdo.wifi` FSIM (see [[WiFi-FSIM]]) is used for both single-sided and full owner modes. No separate FSIM is needed - the client's profile determines behavior:

| Mode | fdo.wifi Behavior |
|------|-------------------|
| Single-Sided | Accept networks but downgrade all trust levels to 0 |
| Full Owner | Accept networks with trust levels as specified |

#### 2.2 FSIM Access Control

Implement FSIM filtering based on attestation mode:

```go
type FSIMFilter struct {
    mode AttestationMode
}

func (f *FSIMFilter) AllowFSIM(fsimName string) bool {
    if f.mode == ModeSingleSided {
        // Only devmod and fdo.wifi allowed in single-sided mode
        return fsimName == "devmod" || fsimName == "fdo.wifi"
    }
    return true // All FSIMs allowed in full owner mode
}

func (f *FSIMFilter) AdvertisedModules() []string {
    if f.mode == ModeSingleSided {
        return []string{"fdo.wifi"}  // Only advertise WiFi
    }
    return f.allSupportedModules()   // Advertise all capabilities
}
```

#### 2.3 Trust Level Enforcement

Implement trust level downgrade for single-sided mode:

```go
func (f *WiFiFSIM) ApplyNetwork(state *DeviceState, network *WiFiNetwork) error {
    // In single-sided mode, always downgrade trust level
    if state.AttestationMode == ModeSingleSided && network.TrustLevel > 0 {
        log.Debug("Single-sided mode: downgrading trust_level from %d to 0", network.TrustLevel)
        network.TrustLevel = 0  // Silently downgrade, not an error
    }
    
    return f.configureNetwork(network)
}
```

#### 2.4 Minimal devmod Implementation

Implement devmod data filtering for single-sided mode:

```go
func (d *DevmodFSIM) ReportDeviceInfo(state *DeviceState) map[string]any {
    info := map[string]any{
        "active":     true,
        "nummodules": len(state.AdvertisedModules),
        "modules":    state.AdvertisedModules,
        "sep":        ";",
    }
    
    if state.AttestationMode == ModeSingleSided {
        // Minimal profile: omit identifying information
        info["device"]  = ""
        info["serial"]  = ""
        info["os"]      = ""
        info["version"] = ""
        info["arch"]    = ""
    } else {
        // Full profile: report all device information
        info["device"]  = state.DeviceType
        info["serial"]  = state.SerialNumber
        info["os"]      = state.OS
        info["version"] = state.OSVersion
        info["arch"]    = state.Architecture
    }
    
    return info
}
```

### Phase 3: Client Implementation

#### 3.1 Device Client Changes

Update FDO client to:

- Detect Wi-Fi Setup services via DHCP Option 223
- Initiate single-sided mode automatically
- Apply only Wi-Fi configuration from fdo.wifi-config FSIM

#### 3.2 Network Transition Logic

Implement network switching:

```go
func HandleWifiConfig(config WifiConfig) error {
    // 1. Apply Wi-Fi configuration
    if err := configureWifi(config); err != nil {
        return err
    }
    
    // 2. Disconnect from current network
    if err := disconnectCurrentNetwork(); err != nil {
        return err
    }
    
    // 3. Connect to new Wi-Fi network
    if err := connectToWifi(config); err != nil {
        return err
    }
    
    // 4. Restart onboarding process in double-sided mode
    return restartOnboarding()
}
```

#### 3.3 State Persistence

Ensure state survives network transitions:

```go
type PersistentState struct {
    OnboardingMode OnboardingMode
    WifiConfigured  bool
    LastAttempt     time.Time
    ServiceHistory  []ServiceRecord
}
```

### Phase 4: Security Enhancements

#### 4.1 Information Leakage Prevention

Ensure single-sided mode cannot leak device info:

```go
func (f *DeviceInfoFSIM) Execute(state *DeviceState) error {
    if state.OnboardingMode == ModeSingleSided {
        return errors.New("device info access blocked in single-sided mode")
    }
    // Existing implementation...
}
```

#### 4.2 Rate Limiting

Implement enhanced rate limiting for single-sided mode:

```go
type RateLimiter struct {
    singleSidedAttempts map[string]int
    doubleSidedAttempts map[string]int
    maxSingleAttempts   int
    maxDoubleAttempts   int
}
```

#### 4.3 Audit Logging

Add comprehensive logging for single-sided operations:

```go
type AuditLog struct {
    Timestamp   time.Time
    DeviceID    string
    Mode        OnboardingMode
    ServiceType string
    Operation   string
    Success     bool
}
```

## Development Tasks

### Priority 1: Core Protocol Changes

- [ ] Add single-sided mode detection
- [ ] Implement Owner verification bypass
- [ ] Create mode state management
- [ ] Update TO2 protocol flow

### Priority 2: FSIM Implementation

- [ ] Create fdo.wifi-config FSIM specification
- [ ] Implement FSIM access control
- [ ] Update existing FSIMs with mode checks
- [ ] Add FSIM filtering logic

### Priority 3: Client Integration

- [ ] Update device client for single-sided mode
- [ ] Implement network transition logic
- [ ] Add state persistence across network changes
- [ ] Create restart mechanism for double-sided onboarding

### Priority 4: Security & Testing

- [ ] Implement information leakage prevention
- [ ] Add enhanced rate limiting
- [ ] Create comprehensive audit logging
- [ ] Develop test suite for single-sided scenarios

### Priority 5: Documentation & Deployment

- [ ] Update FDO specification
- [ ] Create deployment guides
- [ ] Add security analysis documentation
- [ ] Develop troubleshooting guides

## Security Considerations

### Threat Model

#### Malicious Wi-Fi Setup Service

- **Risk**: Can provide malicious network credentials
- **Mitigation**: Final onboarding fails without legitimate Owner
- **Impact**: Temporary network exposure only

#### Information Leakage

- **Risk**: Device information exposure in single-sided mode
- **Mitigation**: Block all non-Wi-Fi FSIMs
- **Impact**: Minimal exposure, no persistent compromise

#### Replay Attacks

- **Risk**: Replayed single-sided attestation
- **Mitigation**: Standard FDO replay protection mechanisms
- **Impact**: Prevented by existing cryptographic protections

### Security Properties

1. **Device Authentication**: Strong cryptographic proof of device identity
2. **Limited Exposure**: Only Wi-Fi credentials provisioned
3. **Fail-Safe**: Malicious networks cannot complete final onboarding
4. **Information Protection**: No device info leakage in single-sided mode

## Testing Strategy

### Unit Tests

- Single-sided mode detection
- FSIM access control
- Network transition logic
- State persistence

### Integration Tests

- End-to-end single-sided onboarding
- Network switching scenarios
- Security boundary testing
- Rate limiting verification

### Security Tests

- Information leakage prevention
- Malicious service handling
- Replay attack resistance
- Cryptographic verification

## Deployment Considerations

### Backward Compatibility

- Existing double-sided onboarding unchanged
- New single-sided mode is additive
- No breaking changes to existing deployments

### Configuration

- DHCP Option 223 for Wi-Fi Setup service discovery
- Manufacturer-specific Rendezvous list support
- Configurable rate limiting parameters

### Monitoring

- Single-sided mode usage metrics
- Success/failure rate tracking
- Security event monitoring
- Performance impact assessment

## Timeline

### Phase 1 (Weeks 1-2): Protocol Layer

- Core protocol changes
- Mode detection logic
- Basic testing framework

### Phase 2 (Weeks 3-4): FSIM Layer

- fdo.wifi-config implementation
- Access control mechanisms
- FSIM updates

### Phase 3 (Weeks 5-6): Client Integration

- Device client updates
- Network transition logic
- State management

### Phase 4 (Weeks 7-8): Security & Testing

- Security enhancements
- Comprehensive testing
- Performance optimization

### Phase 5 (Weeks 9-10): Documentation & Deployment

- Documentation updates
- Deployment guides
- Final validation

## Success Criteria

1. **Functional**: Devices can obtain Wi-Fi credentials via single-sided mode
2. **Secure**: No information leakage in single-sided mode
3. **Compatible**: Existing double-sided onboarding unchanged
4. **Reliable**: Robust network transition and state management
5. **Testable**: Comprehensive test coverage for all scenarios

## Conclusion

This strategy provides a secure, implementable approach to single-sided FDO for Wi-Fi onboarding. By creating a dedicated Wi-Fi config FSIM and implementing strict access controls, we can enable the required functionality while maintaining strong security boundaries.

The phased approach allows for incremental development and testing, ensuring each component is thoroughly validated before integration. The result will be a robust solution that addresses the Wi-Fi onboarding challenge without compromising FDO's security model.
