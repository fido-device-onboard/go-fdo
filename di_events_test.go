// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/fido-device-onboard/go-fdo/protocol"
)

func TestDIServerEvents(t *testing.T) {
	defer UnregisterAllEventHandlers()

	var events []Event
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Register event handler to capture all events
	RegisterEventHandler(EventHandlerFunc(func(ctx context.Context, event Event) {
		mu.Lock()
		events = append(events, event)
		mu.Unlock()
		wg.Done()
	}))

	ctx := context.Background()

	// Test DI started event by creating a simple message
	// We can't easily test setCredentials without proper setup,
	// so let's just test the event emission directly

	// Test DI started event emission
	wg.Add(1)
	EmitDIStarted(ctx)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()

	// Check that we received the DI started event
	if len(events) == 0 {
		t.Error("Expected at least one event")
		return
	}

	// The first event should be DI started
	if events[0].Type != EventTypeDIStarted {
		t.Errorf("Expected DI started event, got %v", events[0].Type)
	}
}

func TestDIErrorEvent(t *testing.T) {
	defer UnregisterAllEventHandlers()

	var receivedEvent Event
	var wg sync.WaitGroup
	wg.Add(1)

	RegisterEventHandler(EventHandlerFunc(func(ctx context.Context, event Event) {
		receivedEvent = event
		wg.Done()
	}))

	server := &DIServer[any]{}
	ctx := context.Background()

	// Simulate an error message
	errMsg := protocol.ErrorMessage{
		Code:      500,
		ErrString: "Test error",
	}

	// Call HandleError - this should emit DI failed event
	server.HandleError(ctx, errMsg)
	wg.Wait()

	if receivedEvent.Type != EventTypeDIFailed {
		t.Errorf("Expected DI failed event, got %v", receivedEvent.Type)
	}

	if receivedEvent.Error == nil {
		t.Error("Expected error to be set")
	}

	// Check that the error contains our test error message
	errorStr := receivedEvent.Error.Error()
	if errorStr[:12] != "DI error: 19" {
		t.Errorf("Expected error message to start with 'DI error: 19', got %s", errorStr[:20])
	}

	if !strings.Contains(errorStr, "Test error") {
		t.Errorf("Expected error to contain 'Test error', got %v", errorStr)
	}
}
