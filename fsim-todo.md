# FIDO Service Info Modules (FSIM) - Improvement Tracking

## 1. fdo.wifi-setup.md

### Strengths

- Well-defined authentication types (open, wpa2-psk, wpa3-psk, wpa3-enterprise)
- Clear message flow between device and owner
- Good coverage of common WiFi configuration parameters
- Explicit conditional requirements for different auth types

### Areas for Improvement

#### Security

- [X] Add support for WPA3-SAE (Simultaneous Authentication of Equals)
- [ ] Define minimum key length requirements for PSK
- [ ] Add certificate validation requirements for WPA3-Enterprise
- [ ] Add security considerations section

#### Features

- [ ] Add support for hidden SSIDs
- [ ] REVIEW 802.1X fast roaming (802.11r) support
- [ ] REVIEW Hotspot 2.0/Passpoint support
- [ ] Add support for WPA3-Enterprise 192-bit security

#### Documentation

- [ ] Add example exchanges
- [ ] Document error handling
- [ ] Add security considerations

---

## 2. fdo.payload.md

### Strengths

- Clear separation of concerns
- Good use of MIME types
- Support for chunked transfers

### Areas for Improvement

#### Security

- [ ] Add payload signing/verification
- [ ] Define size limits for chunks
- [ ] Add integrity verification

#### Features

- [ ] Add payload prioritization
- [ ] Implement retry mechanism
- [ ] Add progress tracking

#### Documentation

- [ ] Add sequence diagrams
- [ ] Document error recovery
- [ ] Add example exchanges

---

## 3. fdo.sysconfig.md

### Strengths

- Simple parameter-value model
- Clear response semantics
- Multiple parameters per message

### Areas for Improvement

#### Security

- [ ] Add parameter validation
- [ ] Implement access control
- [ ] Add encryption for sensitive values

#### Features

- [ ] Define standard parameters
- [ ] Add parameter metadata
- [ ] Implement parameter versioning

#### Documentation

- [ ] Add parameter reference
- [ ] Document security model
- [ ] Add example configurations

---

## 4. FDO 2.0 Module System Architecture

### Current State

FDO 2.0 currently uses hardcoded sysconfig responses in `to2_server_v200.go` (lines 397-431) instead of the proper module state machine used by FDO 1.01.

### Issues with Current Implementation

- **Bypasses module system**: Hardcoded responses instead of using `SysConfigOwner` module
- **No state machine**: Doesn't use devmod→sysconfig→nextmodule progression
- **Not scalable**: Hardcoded responses can't adapt to different configurations
- **Inconsistent**: Different architecture from FDO 1.01's proven module system

### Required Changes

#### High Priority

- [ ] **Replace hardcoded sysconfig in FDO 2.0**: Remove the "Simple fix" in `to2_server_v200.go` lines 397-431
- [ ] **Implement proper module state machine**: Use the same `ownerSvcInfo20()` → module progression as FDO 1.01
- [ ] **Ensure devmod→sysconfig transition works**: Verify the module state machine works correctly with FDO 2.0 protocol messages
- [ ] **Test with varying module counts**: Ensure the state machine works with 2-chunk vs 3-chunk devmod scenarios

#### Medium Priority

- [ ] **Unify module systems**: Ensure FDO 1.01 and FDO 2.0 use the same module architecture
- [ ] **Add FDO 2.0 specific module tests**: Verify all FSIMs work with FDO 2.0 protocol
- [ ] **Document architectural differences**: Clearly explain why FDO 2.0 was hardcoded and how to fix it

#### Low Priority

- [ ] **Performance optimization**: Ensure FDO 2.0 module performance matches hardcoded version
- [ ] **Backward compatibility**: Ensure existing FDO 2.0 deployments continue to work

### Technical Notes

The issue is that FDO 2.0's `ownerSvcInfo20()` function bypasses the module system entirely, while FDO 1.01's `ownerServiceInfo()` properly uses the module state machine. This creates architectural inconsistency and prevents proper module progression in FDO 2.0.

---

## Cross-Cutting Concerns

### Standardization

- [ ] Create common error codes
- [ ] Standardize response formats
- [ ] Define common patterns

### Security

- [ ] Add security considerations to all FSIMs
- [ ] Define data sensitivity levels
- [ ] Document authentication/authorization

### Documentation

- [ ] Add sequence diagrams
- [ ] Include example exchanges
- [ ] Document error recovery

### Testing

- [ ] Define conformance tests
- [ ] Add negative test cases
- [ ] Document edge cases

---

## Implementation Priorities

### High Priority

1. **Fix FDO 2.0 module system architecture** (replace hardcoded responses)
2. Security hardening for all FSIMs
3. Standardized error handling
4. Complete documentation

### Medium Priority

1. Missing features
2. Enhanced validation
3. Testing framework

### Low Priority

1. Advanced features
2. Optimization
3. Extended validation

---

## Notes

- All changes should maintain backward compatibility
- Security fixes take highest priority
- Documentation should be updated with any changes
- **FDO 2.0 module system fix is critical for architectural consistency**
