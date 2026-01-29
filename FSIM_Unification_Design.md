# FDO FSIM Unification Design Document

## Objective
Consolidate FDO 1.0.1 and 2.0 FSIM handling code to eliminate duplicate implementations and improve maintainability.

## Current State Analysis

### Problem
- 1.0.1: Has working `ownerServiceInfo` method with proper module state persistence
- 2.0: Has broken `ownerSvcInfo20` method that loses module state
- Current Fix: 2.0 wrapper converts to 1.0.1 format, calls 1.0.1, converts back

### Issues with Current Wrapper Approach
1. **Performance Overhead**: CBOR encode/decode on every call
2. **Type Safety**: Runtime conversions instead of compile-time safety
3. **Maintenance**: Two separate code paths to maintain
4. **Complexity**: Wrapper logic obscures the real flow
5. **Debugging**: Hard to trace through conversion layers

## Phase 2: Extract Common Logic

### 2.1 Identify Core Logic Components

From the working 1.0.1 `ownerServiceInfo` method, these are the core components:

```go
// Core components to extract:
1. Module state machine management
2. Service info processing loop
3. Devmod handling logic
4. Module persistence logic
5. Service info production logic
```

### 2.2 Proposed Shared Method Structure

```go
// Core unified processing method
func (s *TO2Server) processServiceInfoCore(ctx context.Context, req ServiceInfoRequest) (*ServiceInfoResponse, error) {
    // 1. Parse incoming service info
    // 2. Handle devmod if needed
    // 3. Process module state machine
    // 4. Handle module blocking/resume
    // 5. Produce service info from current module
    // 6. Return response
}
```

### 2.3 Core Logic Breakdown

#### Component 1: Service Info Parsing
```go
type ServiceInfoRequest struct {
    ServiceInfo       []*serviceinfo.KV
    IsMoreServiceInfo bool
    SourceVersion     string // "1.0.1" or "2.0"
}

func parseServiceInfo(data interface{}) (*ServiceInfoRequest, error) {
    // Handle both 1.0.1 io.Reader and 2.0 DeviceSvcInfo20Msg
}
```

#### Component 2: Devmod Handling
```go
func (s *TO2Server) handleDevmod(ctx context.Context, req *ServiceInfoRequest) (string, serviceinfo.OwnerModule, error) {
    // Extract the devmod logic from 1.0.1 ownerServiceInfo
    // Handle devmod state, modules, completion
}
```

#### Component 3: Module State Machine
```go
func (s *TO2Server) processModuleStateMachine(ctx context.Context, req *ServiceInfoRequest, moduleName string, module serviceinfo.OwnerModule) (*ServiceInfoResponse, error) {
    // Extract the module processing loop
    // Handle blocking, completion, advancement
}
```

#### Component 4: Module Persistence
```go
func (s *TO2Server) persistModuleState(ctx context.Context, moduleName string, module serviceinfo.OwnerModule) error {
    // Extract the module persistence logic
}
```

#### Component 5: Service Info Production
```go
func (s *TO2Server) produceServiceInfo(ctx context.Context, moduleName string, module serviceinfo.OwnerModule) ([]*serviceinfo.KV, bool, error) {
    // Extract the produceOwnerServiceInfo logic
}
```

## Phase 3: Create Unified Types and Interfaces

### 3.1 Unified Request/Response Types

```go
// Unified request that works for both versions
type UnifiedServiceInfoRequest struct {
    ServiceInfo       []*serviceinfo.KV
    IsMoreServiceInfo bool
    SourceVersion     Version
    RawData          interface{} // Keep original for debugging
}

// Unified response that works for both versions
type UnifiedServiceInfoResponse struct {
    ServiceInfo       []*serviceinfo.KV
    IsMoreServiceInfo bool
    IsDone            bool
    TargetVersion     Version
}

type Version string
const (
    Version101 Version = "1.0.1"
    Version200 Version = "2.0"
)
```

### 3.2 Unified Interface

```go
// Core FSIM processing interface
type FSIMProcessor interface {
    ProcessServiceInfo(ctx context.Context, req *UnifiedServiceInfoRequest) (*UnifiedServiceInfoResponse, error)
}

// Implementation by TO2Server
func (s *TO2Server) ProcessServiceInfo(ctx context.Context, req *UnifiedServiceInfoRequest) (*UnifiedServiceInfoResponse, error) {
    // The unified core logic
}
```

### 3.3 Version-Specific Adapters

```go
// 1.0.1 Adapter
func (s *TO2Server) ownerServiceInfo(ctx context.Context, msg io.Reader) (*ownerServiceInfo, error) {
    req, err := s.adapt101Request(msg)
    if err != nil {
        return nil, err
    }
    
    resp, err := s.ProcessServiceInfo(ctx, req)
    if err != nil {
        return nil, err
    }
    
    return s.adapt101Response(resp)
}

// 2.0 Adapter
func (s *TO2Server) ownerServiceInfo20(ctx context.Context, req *DeviceSvcInfo20Msg) (*OwnerSvcInfo20Msg, error) {
    unifiedReq, err := s.adapt200Request(req)
    if err != nil {
        return nil, err
    }
    
    resp, err := s.ProcessServiceInfo(ctx, unifiedReq)
    if err != nil {
        return nil, err
    }
    
    return s.adapt200Response(resp)
}
```

## Implementation Strategy

### Step 2.1: Extract Core Logic
1. Copy working 1.0.1 `ownerServiceInfo` to `processServiceInfoCore`
2. Replace version-specific parts with interfaces
3. Add comprehensive logging

### Step 2.2: Create Adapters
1. Create `adapt101Request/Response` functions
2. Create `adapt200Request/Response` functions
3. Ensure zero behavior change

### Step 2.3: Test Parity
1. Run existing tests against new implementation
2. Compare logs between old and new
3. Verify identical behavior

### Step 3.1: Define Unified Types
1. Create `UnifiedServiceInfoRequest/Response`
2. Define version constants
3. Add validation methods

### Step 3.2: Implement Interface
1. Make TO2Server implement FSIMProcessor
2. Replace core logic with interface call
3. Remove duplicate code

### Step 3.3: Optimize
1. Eliminate unnecessary conversions
2. Add type safety checks
3. Optimize performance

## Benefits of This Design

### Immediate Benefits
- **Single Source of Truth**: One core FSIM processor
- **Maintainability**: Fix bugs in one place
- **Testing**: Test core logic once
- **Debugging**: Clearer call stack

### Long-term Benefits
- **Performance**: Eliminate CBOR conversions
- **Type Safety**: Compile-time checks
- **Extensibility**: Easy to add new versions
- **Clean Architecture**: Clear separation of concerns

## Migration Risks and Mitigations

### Risk 1: Behavior Changes
- **Mitigation**: Extensive testing and log comparison
- **Fallback**: Keep old implementation as backup

### Risk 2: Performance Regression
- **Mitigation**: Benchmark before/after
- **Optimization**: Profile and optimize hot paths

### Risk 3: Breaking Existing Code
- **Mitigation**: Maintain same public interfaces
- **Testing**: Run full test suite

## Success Criteria

1. **Functional Parity**: Identical behavior to current working system
2. **Performance**: No regression in throughput/latency
3. **Maintainability**: Single code path for FSIM logic
4. **Testability**: Core logic can be tested independently
5. **Extensibility**: Easy to add future FDO versions

## Next Steps

1. **Implement Phase 2**: Extract core logic to shared method
2. **Test Thoroughly**: Ensure no behavior changes
3. **Implement Phase 3**: Create unified types and interfaces
4. **Optimize**: Eliminate conversion overhead
5. **Clean Up**: Remove old duplicate implementations

---

*This design document provides a roadmap for unifying FDO FSIM handling while maintaining backward compatibility and improving the overall architecture.*

## Phase 4: Implementation Details

### 4.1 Core Logic Extraction Strategy

#### Step 4.1.1: Identify Extractable Components

From the working 1.0.1 `ownerServiceInfo` method in `to2.go`:

```go
// Current 1.0.1 structure:
func (s *TO2Server) ownerServiceInfo(ctx context.Context, msg io.Reader) (*ownerServiceInfo, error) {
    // 1. Parse deviceServiceInfo from io.Reader
    // 2. Handle devmod state (lines 1658-1664)
    // 3. Set context values (GUID, voucher, cert chain) (lines 1673-1688)
    // 4. Process service info chunks (lines 1692-1720)
    // 5. Handle devmod completion (lines 1725-1768)
    // 6. Produce service info if not blocked (lines 1771-1773)
    // 7. Persist module state (lines 1776-1780)
    // 8. Return response (lines 1782-1786)
}
```

#### Step 4.1.2: Extract to Core Method

```go
// Proposed core method:
func (s *TO2Server) processServiceInfoCore(ctx context.Context, req *CoreServiceInfoRequest) (*CoreServiceInfoResponse, error) {
    // 1. Validate request
    if err := s.validateServiceInfoRequest(req); err != nil {
        return nil, err
    }
    
    // 2. Handle devmod if applicable
    if moduleName, module, err := s.handleDevmodIfNeeded(ctx, req); err == nil {
        return s.processDevmodModule(ctx, req, moduleName, module)
    }
    
    // 3. Process regular module state machine
    return s.processRegularModule(ctx, req)
}
```

### 4.2 Type Definitions

#### Core Types
```go
// Core request type (version-agnostic)
type CoreServiceInfoRequest struct {
    ServiceInfo       []*serviceinfo.KV
    IsMoreServiceInfo bool
    SourceVersion     Version
    Context           context.Context
    
    // Internal state
    deviceGUID        []byte
    voucher          *Voucher
    deviceCertChain  []*x509.Certificate
}

// Core response type (version-agnostic)
type CoreServiceInfoResponse struct {
    ServiceInfo       []*serviceinfo.KV
    IsMoreServiceInfo bool
    IsDone            bool
    TargetVersion     Version
    
    // Internal state
    moduleAdvanced    bool
    modulePersisted   bool
}
```

#### Version-Specific Adapters
```go
// 1.0.1 Adapter
type ServiceInfo101Adapter struct{}

func (a *ServiceInfo101Adapter) RequestFromReader(msg io.Reader) (*CoreServiceInfoRequest, error) {
    var deviceInfo deviceServiceInfo
    if err := cbor.NewDecoder(msg).Decode(&deviceInfo); err != nil {
        return nil, fmt.Errorf("error decoding TO2.DeviceServiceInfo request: %w", err)
    }
    
    return &CoreServiceInfoRequest{
        ServiceInfo:       deviceInfo.ServiceInfo,
        IsMoreServiceInfo: deviceInfo.IsMoreServiceInfo,
        SourceVersion:     Version101,
    }, nil
}

func (a *ServiceInfo101Adapter) ResponseToCore(resp *ownerServiceInfo) (*CoreServiceInfoResponse, error) {
    return &CoreServiceInfoResponse{
        ServiceInfo:       resp.ServiceInfo,
        IsMoreServiceInfo: resp.IsMoreServiceInfo,
        IsDone:            resp.IsDone,
        TargetVersion:     Version101,
    }, nil
}

// 2.0 Adapter
type ServiceInfo200Adapter struct{}

func (a *ServiceInfo200Adapter) RequestFromMessage(req *DeviceSvcInfo20Msg) (*CoreServiceInfoRequest, error) {
    return &CoreServiceInfoRequest{
        ServiceInfo:       req.ServiceInfo,
        IsMoreServiceInfo: req.IsMoreServiceInfo,
        SourceVersion:     Version200,
    }, nil
}

func (a *ServiceInfo200Adapter) ResponseFromCore(resp *CoreServiceInfoResponse) (*OwnerSvcInfo20Msg, error) {
    return &OwnerSvcInfo20Msg{
        ServiceInfo:       resp.ServiceInfo,
        IsMoreServiceInfo: resp.IsMoreServiceInfo,
        IsDone:            resp.IsDone,
    }, nil
}
```

### 4.3 Module State Machine Unification

#### Current State Machine Issues
```go
// Problem: 2.0 loses state between calls
// First call: module = fdo.payload, complete = false
// Second call: module = nil (state lost)

// Solution: Unified state management
type ModuleStateManager struct {
    currentModule     string
    currentModuleImpl serviceinfo.OwnerModule
    moduleState      map[string]interface{}
    statePersisted    bool
}

func (m *ModuleStateManager) GetCurrentModule(ctx context.Context) (string, serviceinfo.OwnerModule, error) {
    // Check if we have persisted state
    if m.currentModule != "" && m.currentModuleImpl != nil {
        return m.currentModule, m.currentModuleImpl, nil
    }
    
    // Get next module from underlying Modules
    moduleName, module, err := m.Modules.Module(ctx)
    if err != nil || module == nil {
        return "", nil, err
    }
    
    // Cache the module
    m.currentModule = moduleName
    m.currentModuleImpl = module
    return moduleName, module, nil
}

func (m *ModuleStateManager) AdvanceModule(ctx context.Context) error {
    // Clear current module cache
    m.currentModule = ""
    m.currentModuleImpl = nil
    m.statePersisted = false
    
    // Advance underlying module state machine
    _, err := m.Modules.NextModule(ctx)
    return err
}

func (m *ModuleStateManager) PersistModuleState(ctx context.Context, moduleName string, module serviceinfo.OwnerModule) error {
    if persistable, ok := s.Modules.(serviceinfo.ModulePersister); ok {
        if err := persistable.PersistModule(ctx, moduleName, module); err != nil {
            return fmt.Errorf("error persisting service info module %q state: %w", moduleName, err)
        }
        m.statePersisted = true
    }
    return nil
}
```

## Phase 5: Testing Strategy

### 5.1 Parity Testing

#### Test Matrix
```go
type ParityTest struct {
    Name           string
    Version101     TestScenario
    Version200     TestScenario
    ExpectedResult ExpectedBehavior
}

type TestScenario struct {
    InitialServiceInfo []*serviceinfo.KV
    IsMoreServiceInfo  bool
    ModuleState        ModuleState
    ExpectedResponse   interface{}
}

type ExpectedBehavior struct {
    ResponseServiceInfo []*serviceinfo.KV
    IsMoreServiceInfo   bool
    IsDone             bool
    ModuleAdvanced     bool
    Error              error
}
```

#### Test Cases
```go
var parityTests = []ParityTest{
    {
        Name: "Empty service info, no modules",
        Version101: TestScenario{
            InitialServiceInfo: []*serviceinfo.KV{},
            IsMoreServiceInfo:  false,
            ModuleState:        NoModulesState,
        },
        Version200: TestScenario{
            InitialServiceInfo: []*serviceinfo.KV{},
            IsMoreServiceInfo:  false,
            ModuleState:        NoModulesState,
        },
        ExpectedResult: ExpectedBehavior{
            ResponseServiceInfo: []*serviceinfo.KV{},
            IsMoreServiceInfo:   false,
            IsDone:             true,
            ModuleAdvanced:     false,
        },
    },
    {
        Name: "Sysconfig module, complete",
        Version101: TestScenario{
            InitialServiceInfo: []*serviceinfo.KV{
                {Key: "fdo.sysconfig:active", Value: []byte{0xf5}},
            },
            IsMoreServiceInfo: false,
            ModuleState:       SysconfigActiveState,
        },
        Version200: TestScenario{
            InitialServiceInfo: []*serviceinfo.KV{
                {Key: "fdo.sysconfig:active", Value: []byte{0xf5}},
            },
            IsMoreServiceInfo: false,
            ModuleState:       SysconfigActiveState,
        },
        ExpectedResult: ExpectedBehavior{
            ResponseServiceInfo: []*serviceinfo.KV{
                {Key: "fdo.sysconfig:set", Value: sysconfigSetValue},
            },
            IsMoreServiceInfo: false,
            IsDone:             false,
            ModuleAdvanced:     false,
        },
    },
    {
        Name: "Payload module, blocked (RequireAck)",
        Version101: TestScenario{
            InitialServiceInfo: []*serviceinfo.KV{
                {Key: "fdo.payload:active", Value: []byte{0xf5}},
            },
            IsMoreServiceInfo: false,
            ModuleState:       PayloadActiveState,
        },
        Version200: TestScenario{
            InitialServiceInfo: []*serviceinfo.KV{
                {Key: "fdo.payload:active", Value: []byte{0xf5}},
            },
            IsMoreServiceInfo: false,
            ModuleState:       PayloadActiveState,
        },
        ExpectedResult: ExpectedBehavior{
            ResponseServiceInfo: []*serviceinfo.KV{
                {Key: "fdo.payload:payload-begin", Value: payloadBeginValue},
                {Key: "fdo.payload:payload-data", Value: payloadDataValue},
            },
            IsMoreServiceInfo: true,
            IsDone:             false,
            ModuleAdvanced:     false,
        },
    },
}
```

### 5.2 Performance Testing

#### Benchmark Scenarios
```go
func BenchmarkServiceInfoProcessing(b *testing.B) {
    scenarios := []struct {
        Name     string
        Setup    func() *TestContext
        Teardown func(*TestContext)
    }{
        {
            Name: "101_Original",
            Setup: func() *TestContext {
                return setup101Test()
            },
            Teardown: teardownTest,
        },
        {
            Name: "200_Original",
            Setup: func() *TestContext {
                return setup200Test()
            },
            Teardown: teardownTest,
        },
        {
            Name: "Unified_Core",
            Setup: func() *TestContext {
                return setupUnifiedTest()
            },
            Teardown: teardownTest,
        },
        {
            Name: "Unified_Adapter101",
            Setup: func() *TestContext {
                return setupUnified101AdapterTest()
            },
            Teardown: teardownTest,
        },
        {
            Name: "Unified_Adapter200",
            Setup: func() *TestContext {
                return setupUnified200AdapterTest()
            },
            Teardown: teardownTest,
        },
    }
    
    for _, scenario := range scenarios {
        b.Run(scenario.Name, func(b *testing.B) {
            ctx := scenario.Setup()
            defer scenario.Teardown(ctx)
            
            b.ResetTimer()
            for i := 0; i < b.N; i++ {
                // Run the test scenario
                runServiceInfoTest(ctx)
            }
        })
    }
}
```

### 5.3 Integration Testing

#### End-to-End Test Scenarios
```go
type E2ETestScenario struct {
    Name        string
    ServerConfig ServerConfig
    ClientConfig ClientConfig
    ExpectedFlow []ExpectedStep
}

type ExpectedStep struct {
    MessageType    string
    ExpectedFields map[string]interface{}
    ShouldSucceed  bool
}

var e2eTests = []E2ETestScenario{
    {
        Name: "Multi-payload with RequireAck",
        ServerConfig: ServerConfig{
            Payloads: []PayloadConfig{
                {Type: "application/octet-stream", File: "/tmp/payload1.dat", RequireAck: true},
                {Type: "application/invalid", File: "/tmp/payload2.dat", RequireAck: true},
            },
            Sysconfig: SysconfigConfig{
                Hostname: "test-device",
                Timezone: "America/New_York",
            },
        },
        ClientConfig: ClientConfig{
            ExpectedPayloads: 2,
            ExpectedSysconfig: true,
        },
        ExpectedFlow: []ExpectedStep{
            {
                MessageType: "TO2DeviceSvcInfo20MsgType",
                ExpectedFields: map[string]interface{}{
                    "ServiceInfo": "contains devmod modules",
                },
                ShouldSucceed: true,
            },
            {
                MessageType: "TO2OwnerSvcInfo20MsgType", 
                ExpectedFields: map[string]interface{}{
                    "ServiceInfo": "contains sysconfig active",
                },
                ShouldSucceed: true,
            },
            {
                MessageType: "TO2DeviceSvcInfo20MsgType",
                ExpectedFields: map[string]interface{}{
                    "ServiceInfo": "contains sysconfig responses",
                },
                ShouldSucceed: true,
            },
            {
                MessageType: "TO2OwnerSvcInfo20MsgType",
                ExpectedFields: map[string]interface{}{
                    "ServiceInfo": "contains payload begin",
                    "IsMoreServiceInfo": true,
                },
                ShouldSucceed: true,
            },
            {
                MessageType: "TO2DeviceSvcInfo20MsgType",
                ExpectedFields: map[string]interface{}{
                    "ServiceInfo": "contains payload ack",
                },
                ShouldSucceed: true,
            },
            {
                MessageType: "TO2OwnerSvcInfo20MsgType",
                ExpectedFields: map[string]interface{}{
                    "ServiceInfo": "contains second payload begin",
                    "IsMoreServiceInfo": true,
                },
                ShouldSucceed: true,
            },
        },
    },
}
```

## Phase 6: Migration Execution Plan

### 6.1 Phase 2 Execution (Extract Common Logic)

#### Week 1: Preparation
- [ ] Create backup of current working implementation
- [ ] Set up comprehensive test suite
- [ ] Establish baseline performance metrics
- [ ] Create feature branch for unification

#### Week 2: Core Method Creation
- [ ] Copy 1.0.1 `ownerServiceInfo` to `processServiceInfoCore`
- [ ] Replace version-specific dependencies with interfaces
- [ ] Add comprehensive logging and debugging
- [ ] Create unit tests for core method

#### Week 3: Adapter Creation
- [ ] Implement `ServiceInfo101Adapter`
- [ ] Implement `ServiceInfo200Adapter` 
- [ ] Create adapter tests
- [ ] Verify adapter parity with original methods

#### Week 4: Integration and Testing
- [ ] Integrate adapters with existing message handlers
- [ ] Run full parity test suite
- [ ] Performance benchmark comparison
- [ ] Fix any discovered issues

### 6.2 Phase 3 Execution (Unified Types and Interfaces)

#### Week 5: Type System
- [ ] Define unified request/response types
- [ ] Implement version constants and validation
- [ ] Create type conversion utilities
- [ ] Add type safety tests

#### Week 6: Interface Implementation
- [ ] Define `FSIMProcessor` interface
- [ ] Make `TO2Server` implement interface
- [ ] Replace core logic with interface calls
- [ ] Remove duplicate code paths

#### Week 7: Optimization
- [ ] Eliminate unnecessary conversions
- [ ] Optimize hot paths
- [ ] Add compile-time type checks
- [ ] Performance tuning

#### Week 8: Cleanup and Documentation
- [ ] Remove old duplicate implementations
- [ ] Update documentation
- [ ] Code review and final testing
- [ ] Prepare for merge

### 6.3 Risk Mitigation During Migration

#### Continuous Integration
```yaml
# CI Pipeline Steps
- name: Run Parity Tests
  run: |
    go test -v ./fsim/... -tags=parity
    
- name: Run Performance Benchmarks  
  run: |
    go test -bench=. -benchmem ./fsim/...
    
- name: Run Integration Tests
  run: |
    go test -v ./integration/... -tags=e2e
    
- name: Compare Results
  run: |
    ./scripts/compare-results.sh
```

#### Rollback Strategy
- [ ] Keep original implementations as fallback
- [ ] Feature flags to switch between old/new
- [ ] Automated rollback on test failures
- [ ] Gradual rollout with monitoring

#### Monitoring and Alerting
```go
// Add metrics collection
type FSIMMetrics struct {
    ProcessTime    prometheus.HistogramVec
    SuccessRate    prometheus.CounterVec
    ErrorRate      prometheus.CounterVec
    ModuleAdvances prometheus.CounterVec
}

func (m *FSIMMetrics) RecordProcess(version string, duration time.Duration, success bool) {
    m.ProcessTime.WithLabelValues(version).Observe(duration.Seconds())
    if success {
        m.SuccessRate.WithLabelValues(version).Inc()
    } else {
        m.ErrorRate.WithLabelValues(version).Inc()
    }
}
```

## Phase 7: Success Metrics and Validation

### 7.1 Functional Metrics
- [ ] **100% Test Parity**: All existing tests pass with unified implementation
- [ ] **Zero Behavior Changes**: Identical logs and responses
- [ ] **Full Feature Coverage**: All FSIM features work in both versions
- [ ] **Backward Compatibility**: No breaking changes to APIs

### 7.2 Performance Metrics
- [ ] **No Regression**: ≤ 5% performance impact
- [ ] **Memory Efficiency**: Reduced memory allocation
- [ ] **CPU Efficiency**: Lower CPU usage per request
- [ ] **Latency**: Improved or maintained response times

### 7.3 Code Quality Metrics
- [ ] **Reduced Duplication**: ≥ 50% reduction in duplicate code
- [ ] **Improved Testability**: Core logic testable independently
- [ ] **Better Maintainability**: Single source of truth for FSIM
- [ ] **Enhanced Extensibility**: Easy to add new versions

### 7.4 Operational Metrics
- [ ] **Deployment Success**: Smooth deployment without issues
- [ ] **Monitoring Coverage**: All critical paths monitored
- [ ] **Documentation**: Complete and up-to-date documentation
- [ ] **Team Adoption**: Team comfortable with new architecture

---

*This comprehensive design provides a complete roadmap for unifying FDO FSIM handling with minimal risk and maximum benefit.*
