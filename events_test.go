// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/fido-device-onboard/go-fdo/protocol"
)

func TestEventRegistration(t *testing.T) {
	defer UnregisterAllEventHandlers()

	var called bool
	handler := EventHandlerFunc(func(ctx context.Context, event Event) {
		called = true
	})

	RegisterEventHandler(handler)

	// Emit a test event
	EmitDIStarted(context.Background())

	// Give goroutine time to execute
	time.Sleep(50 * time.Millisecond)

	if !called {
		t.Error("Event handler was not called")
	}
}

func TestMultipleHandlers(t *testing.T) {
	defer UnregisterAllEventHandlers()

	var mu sync.Mutex
	count := 0

	for i := 0; i < 3; i++ {
		RegisterEventHandler(EventHandlerFunc(func(ctx context.Context, event Event) {
			mu.Lock()
			count++
			mu.Unlock()
		}))
	}

	EmitDIStarted(context.Background())
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if count != 3 {
		t.Errorf("Expected 3 handler calls, got %d", count)
	}
}

func TestEventData(t *testing.T) {
	defer UnregisterAllEventHandlers()

	var receivedEvent Event
	var wg sync.WaitGroup
	wg.Add(1)

	RegisterEventHandler(EventHandlerFunc(func(ctx context.Context, event Event) {
		receivedEvent = event
		wg.Done()
	}))

	guid := protocol.GUID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

	EmitDICompleted(context.Background(), guid, "test-device")
	wg.Wait()

	if receivedEvent.Type != EventTypeDICompleted {
		t.Errorf("Expected EventTypeDICompleted, got %v", receivedEvent.Type)
	}

	if receivedEvent.GUID == nil {
		t.Error("Expected GUID to be set")
	} else if *receivedEvent.GUID != guid {
		t.Errorf("Expected GUID %v, got %v", guid, *receivedEvent.GUID)
	}

	if receivedEvent.Timestamp.IsZero() {
		t.Error("Expected timestamp to be set")
	}

	data, ok := receivedEvent.Data.(DIEventData)
	if !ok {
		t.Error("Expected DIEventData")
	}

	if data.DeviceInfo != "test-device" {
		t.Errorf("Expected device info 'test-device', got '%s'", data.DeviceInfo)
	}
}

func TestEventTypes(t *testing.T) {
	tests := []struct {
		eventType EventType
		expected  string
	}{
		{EventTypeDIStarted, "DI Started"},
		{EventTypeDICompleted, "DI Completed"},
		{EventTypeTO0Started, "TO0 Started"},
		{EventTypeTO1Completed, "TO1 Completed"},
		{EventTypeTO2Failed, "TO2 Failed"},
		{EventTypeCertValidationFailed, "Certificate Validation Failed"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if tt.eventType.String() != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, tt.eventType.String())
			}
		})
	}
}

func TestHandlerPanicRecovery(t *testing.T) {
	defer UnregisterAllEventHandlers()

	var normalHandlerCalled bool
	var wg sync.WaitGroup
	wg.Add(1)

	// Register a handler that panics
	RegisterEventHandler(EventHandlerFunc(func(ctx context.Context, event Event) {
		panic("test panic")
	}))

	// Register a normal handler that should still be called
	RegisterEventHandler(EventHandlerFunc(func(ctx context.Context, event Event) {
		normalHandlerCalled = true
		wg.Done()
	}))

	EmitDIStarted(context.Background())
	wg.Wait()

	if !normalHandlerCalled {
		t.Error("Normal handler should have been called despite panic in other handler")
	}
}

func TestUnregisterAllHandlers(t *testing.T) {
	var called bool
	handler := EventHandlerFunc(func(ctx context.Context, event Event) {
		called = true
	})

	RegisterEventHandler(handler)
	UnregisterAllEventHandlers()

	EmitDIStarted(context.Background())
	time.Sleep(50 * time.Millisecond)

	if called {
		t.Error("Handler should not have been called after unregistering")
	}
}

func TestCertValidationEvent(t *testing.T) {
	defer UnregisterAllEventHandlers()

	var receivedEvent Event
	var wg sync.WaitGroup
	wg.Add(1)

	RegisterEventHandler(EventHandlerFunc(func(ctx context.Context, event Event) {
		receivedEvent = event
		wg.Done()
	}))

	EmitCertValidationFailed(context.Background(), "CN=test-device", CertValidationErrorExpired, "certificate expired", "test context")
	wg.Wait()

	if receivedEvent.Type != EventTypeCertValidationFailed {
		t.Errorf("Expected EventTypeCertValidationFailed, got %v", receivedEvent.Type)
	}

	if receivedEvent.CertErrorCode == nil {
		t.Error("Expected CertErrorCode to be set")
	} else if *receivedEvent.CertErrorCode != CertValidationErrorExpired {
		t.Errorf("Expected CertValidationErrorExpired, got %v", *receivedEvent.CertErrorCode)
	}

	if receivedEvent.CertErrorMsg != "certificate expired" {
		t.Errorf("Expected error message 'certificate expired', got '%s'", receivedEvent.CertErrorMsg)
	}

	data, ok := receivedEvent.Data.(CertValidationEventData)
	if !ok {
		t.Error("Expected CertValidationEventData")
	}

	if data.CertSubject != "CN=test-device" {
		t.Errorf("Expected cert subject 'CN=test-device', got '%s'", data.CertSubject)
	}

	if data.Context != "test context" {
		t.Errorf("Expected context 'test context', got '%s'", data.Context)
	}
}
