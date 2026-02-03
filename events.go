// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"sync"
	"time"

	"github.com/fido-device-onboard/go-fdo/protocol"
)

// EventType represents the type of FDO event
type EventType int

const (
	// EventTypeUnknown - Unknown event type
	EventTypeUnknown EventType = iota

	// EventTypeDIStarted indicates DI protocol started
	EventTypeDIStarted
	// EventTypeDIAppStartReceived indicates DI.AppStart message received
	EventTypeDIAppStartReceived
	// EventTypeDIVoucherCreated indicates voucher created during DI
	EventTypeDIVoucherCreated
	// EventTypeDICompleted indicates DI protocol completed successfully
	EventTypeDICompleted
	// EventTypeDIFailed indicates DI protocol failed
	EventTypeDIFailed

	// EventTypeTO0Started indicates TO0 protocol started
	EventTypeTO0Started
	// EventTypeTO0BlobRegistered indicates RV blob registered successfully
	EventTypeTO0BlobRegistered
	// EventTypeTO0Completed indicates TO0 protocol completed successfully
	EventTypeTO0Completed
	// EventTypeTO0Failed indicates TO0 protocol failed
	EventTypeTO0Failed

	// EventTypeTO1Started indicates TO1 protocol started
	EventTypeTO1Started
	// EventTypeTO1DeviceLookup indicates device lookup in RV blob store
	EventTypeTO1DeviceLookup
	// EventTypeTO1Completed indicates TO1 protocol completed successfully
	EventTypeTO1Completed
	// EventTypeTO1Failed indicates TO1 protocol failed
	EventTypeTO1Failed

	// EventTypeTO2Started indicates TO2 protocol started
	EventTypeTO2Started
	// EventTypeTO2VoucherVerified indicates ownership voucher verified
	EventTypeTO2VoucherVerified
	// EventTypeTO2DeviceAuthenticated indicates device authenticated successfully
	EventTypeTO2DeviceAuthenticated
	// EventTypeTO2KeyExchangeCompleted indicates key exchange completed
	EventTypeTO2KeyExchangeCompleted
	// EventTypeTO2ServiceInfoStarted indicates service info exchange started
	EventTypeTO2ServiceInfoStarted
	// EventTypeTO2ServiceInfoCompleted indicates service info exchange completed
	EventTypeTO2ServiceInfoCompleted
	// EventTypeTO2Completed indicates TO2 protocol completed successfully
	// This is emitted for both normal (full owner) and single-sided attestation modes.
	// Check the AttestationMode field in TO2EventData to determine which mode was used.
	EventTypeTO2Completed
	// EventTypeTO2SingleSidedComplete indicates single-sided WiFi onboarding completed.
	// This is a more specific event than TO2Completed, emitted only for single-sided mode.
	// Client implementations can use this as a trigger to re-attempt full onboarding
	// using newly received WiFi credentials.
	EventTypeTO2SingleSidedComplete
	// EventTypeTO2Failed indicates TO2 protocol failed
	EventTypeTO2Failed

	// EventTypeCertValidationStarted indicates certificate validation started
	EventTypeCertValidationStarted
	// EventTypeCertValidationSuccess indicates certificate validation succeeded
	EventTypeCertValidationSuccess
	// EventTypeCertValidationFailed indicates certificate validation failed
	EventTypeCertValidationFailed

	// EventTypeVoucherExtended indicates voucher extended to new owner
	EventTypeVoucherExtended
	// EventTypeVoucherReplaced indicates voucher replaced (resale)
	EventTypeVoucherReplaced

	// EventTypeProtocolError indicates protocol-level error occurred
	EventTypeProtocolError
	// EventTypeInternalError indicates internal server error occurred
	EventTypeInternalError
)

// String returns a human-readable description of the event type
func (e EventType) String() string {
	// Use a map for O(1) lookup instead of large switch
	return eventTypeNames[e]
}

// eventTypeNames maps event types to their string representations
var eventTypeNames = map[EventType]string{
	EventTypeUnknown:                 "Unknown Event",
	EventTypeDIStarted:               "DI Started",
	EventTypeDIAppStartReceived:      "DI AppStart Received",
	EventTypeDIVoucherCreated:        "DI Voucher Created",
	EventTypeDICompleted:             "DI Completed",
	EventTypeDIFailed:                "DI Failed",
	EventTypeTO0Started:              "TO0 Started",
	EventTypeTO0BlobRegistered:       "TO0 Blob Registered",
	EventTypeTO0Completed:            "TO0 Completed",
	EventTypeTO0Failed:               "TO0 Failed",
	EventTypeTO1Started:              "TO1 Started",
	EventTypeTO1DeviceLookup:         "TO1 Device Lookup",
	EventTypeTO1Completed:            "TO1 Completed",
	EventTypeTO1Failed:               "TO1 Failed",
	EventTypeTO2Started:              "TO2 Started",
	EventTypeTO2VoucherVerified:      "TO2 Voucher Verified",
	EventTypeTO2DeviceAuthenticated:  "TO2 Device Authenticated",
	EventTypeTO2KeyExchangeCompleted: "TO2 Key Exchange Completed",
	EventTypeTO2ServiceInfoStarted:   "TO2 Service Info Started",
	EventTypeTO2ServiceInfoCompleted: "TO2 Service Info Completed",
	EventTypeTO2Completed:            "TO2 Completed",
	EventTypeTO2SingleSidedComplete:  "TO2 Single-Sided Complete",
	EventTypeTO2Failed:               "TO2 Failed",
	EventTypeCertValidationStarted:   "Certificate Validation Started",
	EventTypeCertValidationSuccess:   "Certificate Validation Success",
	EventTypeCertValidationFailed:    "Certificate Validation Failed",
	EventTypeVoucherExtended:         "Voucher Extended",
	EventTypeVoucherReplaced:         "Voucher Replaced",
	EventTypeProtocolError:           "Protocol Error",
	EventTypeInternalError:           "Internal Error",
}

// Event represents a FDO protocol event
type Event struct {
	// Type of the event
	Type EventType

	// Timestamp when the event occurred
	Timestamp time.Time

	// GUID of the device involved (if applicable)
	GUID *protocol.GUID

	// Protocol version being used
	ProtocolVersion protocol.Version

	// Message type that triggered this event (if applicable)
	MessageType *uint8

	// Error information (if this is an error event)
	Error error

	// Certificate validation error details (if applicable)
	CertErrorCode *CertificateValidationErrorCode
	CertErrorMsg  string

	// Additional context-specific data
	Data EventData
}

// EventData contains type-specific event data
type EventData interface {
	eventData()
}

// DIEventData contains DI-specific event information
type DIEventData struct {
	DeviceInfo      string
	GUID            protocol.GUID
	ManufacturerKey *protocol.PublicKey
}

func (DIEventData) eventData() {}

// TO0EventData contains TO0-specific event information
type TO0EventData struct {
	TTLSeconds   uint32
	RVAddresses  []protocol.RvTO2Addr
	DelegateName string
}

func (TO0EventData) eventData() {}

// TO1EventData contains TO1-specific event information
type TO1EventData struct {
	RVBlob          *protocol.To1d
	DevicePublicKey interface{}
}

func (TO1EventData) eventData() {}

// TO2EventData contains TO2-specific event information
type TO2EventData struct {
	VoucherGUID      protocol.GUID
	KeyExchangeSuite string
	CredentialReuse  bool
	ServiceInfoCount int
	// AttestationMode indicates the type of attestation used:
	// - ModeFullOwner (0): Normal mutual attestation (device and owner verified)
	// - ModeSingleSided (1): Single-sided attestation (device verified, owner not verified)
	// Client implementations can use this to determine next steps after TO2 completes.
	AttestationMode AttestationMode
}

func (TO2EventData) eventData() {}

// CertValidationEventData contains certificate validation event information
type CertValidationEventData struct {
	CertSubject  string
	ChainLength  int
	ErrorCode    CertificateValidationErrorCode
	ErrorMessage string
	Context      string
}

func (CertValidationEventData) eventData() {}

// VoucherEventData contains voucher-related event information
type VoucherEventData struct {
	GUID           protocol.GUID
	PreviousOwner  *protocol.PublicKey
	NewOwner       *protocol.PublicKey
	ExtensionCount int
}

func (VoucherEventData) eventData() {}

// ErrorEventData contains error event information
type ErrorEventData struct {
	ErrorCode    uint16
	ErrorMessage string
	MessageType  uint8
	StackTrace   string
}

func (ErrorEventData) eventData() {}

// EventHandler is the interface that implementations must satisfy to receive FDO events
type EventHandler interface {
	// HandleEvent is called when an FDO event occurs
	// Implementations should not block for long periods as this may impact protocol performance
	HandleEvent(ctx context.Context, event Event)
}

// EventHandlerFunc is a function adapter for EventHandler
type EventHandlerFunc func(ctx context.Context, event Event)

// HandleEvent implements EventHandler
func (f EventHandlerFunc) HandleEvent(ctx context.Context, event Event) {
	f(ctx, event)
}

// eventDispatcher manages event handlers and dispatches events
type eventDispatcher struct {
	mu       sync.RWMutex
	handlers []EventHandler
}

var globalDispatcher = &eventDispatcher{
	handlers: make([]EventHandler, 0),
}

// RegisterEventHandler registers a global event handler
// All registered handlers will receive all FDO events
func RegisterEventHandler(handler EventHandler) {
	globalDispatcher.mu.Lock()
	defer globalDispatcher.mu.Unlock()
	globalDispatcher.handlers = append(globalDispatcher.handlers, handler)
}

// UnregisterAllEventHandlers removes all registered event handlers
// This is primarily useful for testing
func UnregisterAllEventHandlers() {
	globalDispatcher.mu.Lock()
	defer globalDispatcher.mu.Unlock()
	globalDispatcher.handlers = make([]EventHandler, 0)
}

// emitEvent dispatches an event to all registered handlers
func emitEvent(ctx context.Context, event Event) {
	// Set timestamp if not already set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Get protocol version from context if not set
	if event.ProtocolVersion == 0 {
		event.ProtocolVersion = protocol.VersionFromContext(ctx)
	}

	globalDispatcher.mu.RLock()
	handlers := make([]EventHandler, len(globalDispatcher.handlers))
	copy(handlers, globalDispatcher.handlers)
	globalDispatcher.mu.RUnlock()

	// Dispatch to all handlers
	// We dispatch in goroutines to avoid blocking the protocol flow
	// However, we don't wait for handlers to complete
	for _, handler := range handlers {
		h := handler // capture for goroutine
		go func() {
			// Recover from panics in event handlers to prevent crashing the protocol
			defer func() {
				if r := recover(); r != nil {
					// Log panic but don't crash
					// In production, this should be logged properly
					_ = r
				}
			}()
			h.HandleEvent(ctx, event)
		}()
	}
}

// Helper functions to emit specific events

// EmitDIStarted emits a DI started event
func EmitDIStarted(ctx context.Context) {
	emitEvent(ctx, Event{
		Type: EventTypeDIStarted,
	})
}

// EmitDICompleted emits a DI completed event
func EmitDICompleted(ctx context.Context, guid protocol.GUID, deviceInfo string) {
	emitEvent(ctx, Event{
		Type: EventTypeDICompleted,
		GUID: &guid,
		Data: DIEventData{
			GUID:       guid,
			DeviceInfo: deviceInfo,
		},
	})
}

// EmitDIFailed emits a DI failed event
func EmitDIFailed(ctx context.Context, err error) {
	emitEvent(ctx, Event{
		Type:  EventTypeDIFailed,
		Error: err,
	})
}

// EmitTO0Started emits a TO0 started event
func EmitTO0Started(ctx context.Context, guid protocol.GUID) {
	emitEvent(ctx, Event{
		Type: EventTypeTO0Started,
		GUID: &guid,
	})
}

// EmitTO0Completed emits a TO0 completed event
func EmitTO0Completed(ctx context.Context, guid protocol.GUID, ttl uint32) {
	emitEvent(ctx, Event{
		Type: EventTypeTO0Completed,
		GUID: &guid,
		Data: TO0EventData{
			TTLSeconds: ttl,
		},
	})
}

// EmitTO0Failed emits a TO0 failed event
func EmitTO0Failed(ctx context.Context, guid protocol.GUID, err error) {
	emitEvent(ctx, Event{
		Type:  EventTypeTO0Failed,
		GUID:  &guid,
		Error: err,
	})
}

// EmitTO1Started emits a TO1 started event
func EmitTO1Started(ctx context.Context, guid protocol.GUID) {
	emitEvent(ctx, Event{
		Type: EventTypeTO1Started,
		GUID: &guid,
	})
}

// EmitTO1Completed emits a TO1 completed event
func EmitTO1Completed(ctx context.Context, guid protocol.GUID) {
	emitEvent(ctx, Event{
		Type: EventTypeTO1Completed,
		GUID: &guid,
	})
}

// EmitTO1Failed emits a TO1 failed event
func EmitTO1Failed(ctx context.Context, guid protocol.GUID, err error) {
	emitEvent(ctx, Event{
		Type:  EventTypeTO1Failed,
		GUID:  &guid,
		Error: err,
	})
}

// EmitTO2Started emits a TO2 started event
func EmitTO2Started(ctx context.Context, guid protocol.GUID) {
	emitEvent(ctx, Event{
		Type: EventTypeTO2Started,
		GUID: &guid,
	})
}

// EmitTO2Completed emits a TO2 completed event.
// The attestationMode parameter indicates whether this was a normal (ModeFullOwner)
// or single-sided (ModeSingleSided) attestation. For single-sided mode, this function
// also emits EventTypeTO2SingleSidedComplete as a convenience for clients that want
// to specifically handle single-sided completion (e.g., to re-attempt full onboarding).
func EmitTO2Completed(ctx context.Context, guid protocol.GUID, credReuse bool, attestationMode AttestationMode) {
	// Always emit the general TO2Completed event
	emitEvent(ctx, Event{
		Type: EventTypeTO2Completed,
		GUID: &guid,
		Data: TO2EventData{
			VoucherGUID:     guid,
			CredentialReuse: credReuse,
			AttestationMode: attestationMode,
		},
	})

	// For single-sided mode, also emit a specific event as a convenience trigger
	if attestationMode == ModeSingleSided {
		emitEvent(ctx, Event{
			Type: EventTypeTO2SingleSidedComplete,
			GUID: &guid,
			Data: TO2EventData{
				VoucherGUID:     guid,
				CredentialReuse: credReuse,
				AttestationMode: attestationMode,
			},
		})
	}
}

// EmitTO2Failed emits a TO2 failed event
func EmitTO2Failed(ctx context.Context, guid protocol.GUID, err error) {
	emitEvent(ctx, Event{
		Type:  EventTypeTO2Failed,
		GUID:  &guid,
		Error: err,
	})
}

// EmitCertValidationFailed emits a certificate validation failed event
func EmitCertValidationFailed(ctx context.Context, certSubject string, errCode CertificateValidationErrorCode, errMsg string, context string) {
	emitEvent(ctx, Event{
		Type:          EventTypeCertValidationFailed,
		CertErrorCode: &errCode,
		CertErrorMsg:  errMsg,
		Data: CertValidationEventData{
			CertSubject:  certSubject,
			ErrorCode:    errCode,
			ErrorMessage: errMsg,
			Context:      context,
		},
	})
}

// EmitProtocolError emits a protocol error event
func EmitProtocolError(ctx context.Context, guid *protocol.GUID, msgType uint8, errCode uint16, err error) {
	emitEvent(ctx, Event{
		Type:        EventTypeProtocolError,
		GUID:        guid,
		MessageType: &msgType,
		Error:       err,
		Data: ErrorEventData{
			ErrorCode:    errCode,
			ErrorMessage: err.Error(),
			MessageType:  msgType,
		},
	})
}
