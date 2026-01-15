# FDO Event Callback System

## Overview

The FDO event callback system provides a standardized interface for external systems to receive real-time notifications about FDO protocol events. This enables integration with databases, monitoring systems, user interfaces, and other components without requiring log scraping or polling.

## Why Event Callbacks?

While the FDO library is designed as a reusable component, real-world deployments need to:

- **Track device state** in databases for management UIs
- **Monitor operations** with metrics systems (Prometheus, StatsD)
- **Alert on failures** via webhooks (Slack, PagerDuty)
- **Display progress** in real-time user interfaces
- **Audit operations** for compliance and security

The event callback system makes these integrations straightforward and maintainable.

## Core Concepts

### Event Types

Events are categorized by protocol stage:

#### DI (Device Initialization) Events

- `EventTypeDIStarted` - DI protocol started
- `EventTypeDIAppStartReceived` - Device info received
- `EventTypeDIVoucherCreated` - Ownership voucher created
- `EventTypeDICompleted` - DI completed successfully
- `EventTypeDIFailed` - DI failed with error

#### TO0 (Owner to Rendezvous) Events

- `EventTypeTO0Started` - TO0 protocol started
- `EventTypeTO0BlobRegistered` - RV blob registered
- `EventTypeTO0Completed` - TO0 completed successfully
- `EventTypeTO0Failed` - TO0 failed with error

#### TO1 (Device to Rendezvous) Events

- `EventTypeTO1Started` - TO1 protocol started
- `EventTypeTO1DeviceLookup` - Device lookup in RV store
- `EventTypeTO1Completed` - TO1 completed successfully
- `EventTypeTO1Failed` - TO1 failed with error

#### TO2 (Device to Owner) Events

- `EventTypeTO2Started` - TO2 protocol started
- `EventTypeTO2VoucherVerified` - Ownership voucher verified
- `EventTypeTO2DeviceAuthenticated` - Device authenticated
- `EventTypeTO2KeyExchangeCompleted` - Secure channel established
- `EventTypeTO2ServiceInfoStarted` - Service info exchange started
- `EventTypeTO2ServiceInfoCompleted` - Service info exchange completed
- `EventTypeTO2Completed` - TO2 completed successfully
- `EventTypeTO2Failed` - TO2 failed with error

#### Certificate Validation Events

- `EventTypeCertValidationStarted` - Certificate validation started
- `EventTypeCertValidationSuccess` - Certificate validation succeeded
- `EventTypeCertValidationFailed` - Certificate validation failed

#### Error Events

- `EventTypeProtocolError` - Protocol-level error occurred
- `EventTypeInternalError` - Internal server error occurred

### Event Structure

Each event contains:

```go
type Event struct {
    Type            EventType           // Type of event
    Timestamp       time.Time           // When the event occurred
    GUID            *protocol.GUID      // Device GUID (if applicable)
    ProtocolVersion protocol.Version    // FDO protocol version
    MessageType     *uint8              // Protocol message type
    Error           error               // Error information (if error event)
    CertErrorCode   *CertificateValidationErrorCode
    CertErrorMsg    string
    Data            EventData           // Type-specific data
}
```

### Event Data Types

Type-specific data provides additional context:

- **DIEventData** - Device info, GUID, manufacturer key
- **TO0EventData** - TTL, RV addresses, delegate name
- **TO1EventData** - RV blob, device public key
- **TO2EventData** - Voucher GUID, key exchange suite, credential reuse
- **CertValidationEventData** - Certificate subject, error details, context
- **VoucherEventData** - GUID, previous/new owner, extension count
- **ErrorEventData** - Error code, message, stack trace

## Usage

### 1. Implement EventHandler Interface

```go
type MyEventHandler struct {
    db     *sql.DB
    logger *slog.Logger
}

func (h *MyEventHandler) HandleEvent(ctx context.Context, event fdo.Event) {
    // Process the event
    h.logger.Info("FDO Event",
        "type", event.Type.String(),
        "guid", event.GUID,
        "timestamp", event.Timestamp,
    )
    
    // Update database, send metrics, etc.
    if event.GUID != nil {
        h.updateDeviceState(*event.GUID, event.Type)
    }
}
```

### 2. Register Handler

```go
func main() {
    handler := &MyEventHandler{
        db:     db,
        logger: logger,
    }
    
    fdo.RegisterEventHandler(handler)
    
    // Now all FDO protocol operations will emit events to your handler
}
```

### 3. Use Function Adapter for Simple Cases

```go
fdo.RegisterEventHandler(fdo.EventHandlerFunc(func(ctx context.Context, event fdo.Event) {
    if event.Error != nil {
        log.Printf("FDO Error: %s - %v", event.Type, event.Error)
    }
}))
```

## Integration Examples

### Database Integration

Track device onboarding state in a database:

```go
type DatabaseEventLogger struct {
    db *sql.DB
}

func (d *DatabaseEventLogger) HandleEvent(ctx context.Context, event fdo.Event) {
    if event.GUID == nil {
        return
    }
    
    switch event.Type {
    case fdo.EventTypeDICompleted:
        d.db.Exec("INSERT INTO devices (guid, state, timestamp) VALUES (?, ?, ?)",
            event.GUID[:], "DI_COMPLETED", event.Timestamp)
    case fdo.EventTypeTO2Completed:
        d.db.Exec("UPDATE devices SET state = ?, timestamp = ? WHERE guid = ?",
            "ONBOARDED", event.Timestamp, event.GUID[:])
    case fdo.EventTypeDIFailed, fdo.EventTypeTO2Failed:
        errMsg := ""
        if event.Error != nil {
            errMsg = event.Error.Error()
        }
        d.db.Exec("UPDATE devices SET state = ?, error = ?, timestamp = ? WHERE guid = ?",
            "FAILED", errMsg, event.Timestamp, event.GUID[:])
    }
}
```

### Metrics Collection

Export metrics to Prometheus:

```go
type MetricsCollector struct {
    diSuccess    prometheus.Counter
    diFailure    prometheus.Counter
    to2Success   prometheus.Counter
    to2Failure   prometheus.Counter
    certErrors   prometheus.Counter
}

func (m *MetricsCollector) HandleEvent(ctx context.Context, event fdo.Event) {
    switch event.Type {
    case fdo.EventTypeDICompleted:
        m.diSuccess.Inc()
    case fdo.EventTypeDIFailed:
        m.diFailure.Inc()
    case fdo.EventTypeTO2Completed:
        m.to2Success.Inc()
    case fdo.EventTypeTO2Failed:
        m.to2Failure.Inc()
    case fdo.EventTypeCertValidationFailed:
        m.certErrors.Inc()
    }
}
```

### Webhook Notifications

Send alerts to external systems:

```go
type WebhookNotifier struct {
    webhookURL string
    client     *http.Client
}

func (w *WebhookNotifier) HandleEvent(ctx context.Context, event fdo.Event) {
    // Only notify on critical events
    if event.Type == fdo.EventTypeTO2Failed || 
       event.Type == fdo.EventTypeCertValidationFailed {
        
        payload := map[string]interface{}{
            "event_type": event.Type.String(),
            "guid":       event.GUID,
            "timestamp":  event.Timestamp,
            "error":      event.Error.Error(),
        }
        
        jsonData, _ := json.Marshal(payload)
        w.client.Post(w.webhookURL, "application/json", bytes.NewBuffer(jsonData))
    }
}
```

### UI State Management

Provide real-time status updates to web UIs:

```go
type UIStateManager struct {
    mu      sync.RWMutex
    devices map[string]*DeviceState
    updates chan DeviceState
}

type DeviceState struct {
    GUID         string
    State        string
    Progress     int // 0-100
    ErrorMessage string
}

func (u *UIStateManager) HandleEvent(ctx context.Context, event fdo.Event) {
    if event.GUID == nil {
        return
    }
    
    guidStr := fmt.Sprintf("%x", *event.GUID)
    
    u.mu.Lock()
    state := u.devices[guidStr]
    if state == nil {
        state = &DeviceState{GUID: guidStr}
        u.devices[guidStr] = state
    }
    
    // Update progress based on protocol stage
    switch event.Type {
    case fdo.EventTypeDICompleted:
        state.State = "Initialized"
        state.Progress = 25
    case fdo.EventTypeTO1Completed:
        state.State = "Located Owner"
        state.Progress = 50
    case fdo.EventTypeTO2KeyExchangeCompleted:
        state.State = "Secure Channel"
        state.Progress = 75
    case fdo.EventTypeTO2Completed:
        state.State = "Onboarded"
        state.Progress = 100
    }
    u.mu.Unlock()
    
    // Notify UI via WebSocket or SSE
    u.updates <- *state
}
```

## Best Practices

### 1. Non-Blocking Handlers

Event handlers are called asynchronously in goroutines, but should still avoid long-blocking operations:

```go
func (h *MyHandler) HandleEvent(ctx context.Context, event fdo.Event) {
    // Good: Quick operations
    h.metrics.Inc()
    
    // Good: Async processing
    go h.processEventAsync(event)
    
    // Bad: Long-blocking operation
    // time.Sleep(10 * time.Second)
}
```

### 2. Error Recovery

Handlers should recover from panics to avoid disrupting protocol flow:

```go
func (h *MyHandler) HandleEvent(ctx context.Context, event fdo.Event) {
    defer func() {
        if r := recover(); r != nil {
            log.Printf("Event handler panic: %v", r)
        }
    }()
    
    // Handler logic
}
```

Note: The event dispatcher already includes panic recovery, but defensive programming is recommended.

### 3. Context Awareness

Use the provided context for cancellation and timeouts:

```go
func (h *MyHandler) HandleEvent(ctx context.Context, event fdo.Event) {
    select {
    case <-ctx.Done():
        return // Context cancelled
    default:
        // Process event
    }
}
```

### 4. Selective Event Processing

Filter events to only process what you need:

```go
func (h *MyHandler) HandleEvent(ctx context.Context, event fdo.Event) {
    // Only track TO2 events
    if event.Type < fdo.EventTypeTO2Started || event.Type > fdo.EventTypeTO2Failed {
        return
    }
    
    // Process TO2 events
}
```

## Use Cases

### Onboarding Service (Owner)

An onboarding service managing thousands of devices needs to:

- Track device state in PostgreSQL
- Display real-time progress in React UI
- Send metrics to Prometheus
- Alert on failures via PagerDuty

```go
// Register multiple handlers for different purposes
fdo.RegisterEventHandler(NewDatabaseLogger(db))
fdo.RegisterEventHandler(NewMetricsCollector(prometheus))
fdo.RegisterEventHandler(NewUIStateManager(websocketHub))
fdo.RegisterEventHandler(NewAlertManager(pagerduty))
```

### Rendezvous Service

A rendezvous service needs to:

- Track device lookup attempts
- Monitor blob registration success/failure
- Detect suspicious activity patterns

```go
fdo.RegisterEventHandler(NewRVMonitor(db, alerting))
```

### Manufacturing Service (DI)

A manufacturing service needs to:

- Track voucher creation
- Monitor DI success rates by production line
- Integrate with MES (Manufacturing Execution System)

```go
fdo.RegisterEventHandler(NewManufacturingIntegration(mes, metrics))
```

## Testing

### Mock Event Handler

```go
type MockEventHandler struct {
    events []fdo.Event
    mu     sync.Mutex
}

func (m *MockEventHandler) HandleEvent(ctx context.Context, event fdo.Event) {
    m.mu.Lock()
    defer m.mu.Unlock()
    m.events = append(m.events, event)
}

func (m *MockEventHandler) GetEvents() []fdo.Event {
    m.mu.Lock()
    defer m.mu.Unlock()
    return append([]fdo.Event{}, m.events...)
}

// In tests
func TestDIProtocol(t *testing.T) {
    mock := &MockEventHandler{}
    fdo.RegisterEventHandler(mock)
    defer fdo.UnregisterAllEventHandlers()
    
    // Run DI protocol
    // ...
    
    events := mock.GetEvents()
    assert.Contains(t, events, fdo.EventTypeDICompleted)
}
```

## Performance Considerations

- Event handlers run in separate goroutines to avoid blocking protocol flow
- Handlers should complete quickly or spawn their own goroutines for heavy work
- The event system adds minimal overhead (~microseconds per event)
- No events are dropped unless a handler panics

## Security Considerations

Event data may contain sensitive information:

- **GUID** - Device identifier (public)
- **Device Info** - May contain serial numbers, MAC addresses
- **Error Messages** - Should not expose internal system details
- **Certificate Subjects** - Public information

Handlers should:

- Sanitize data before external transmission
- Use secure channels for webhook notifications
- Implement access controls for event data storage
- Follow data retention policies

## Migration from Log Scraping

If you're currently scraping logs, the event system provides:

✅ **Structured data** instead of parsing log strings  
✅ **Real-time notifications** instead of polling  
✅ **Type safety** with Go interfaces  
✅ **Guaranteed delivery** to registered handlers  
✅ **Context preservation** (GUID, protocol version, etc.)  

## Future Enhancements

Potential future improvements:

1. **Event filtering** - Register handlers for specific event types
2. **Event replay** - Store and replay events for debugging
3. **Event batching** - Batch events for high-throughput scenarios
4. **Priority handlers** - Execute critical handlers first
5. **Event middleware** - Transform events before delivery

## Example Code

See `examples/event_integration.go` for complete working examples of:

- Database integration
- Metrics collection
- Webhook notifications
- UI state management
- Function-based handlers

## Support

For questions or issues with the event callback system:

1. Check the example code in `examples/event_integration.go`
2. Review this documentation
3. Open an issue on GitHub with your use case
