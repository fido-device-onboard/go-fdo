// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"sync"
	"testing"

	"github.com/fido-device-onboard/go-fdo/protocol"
)

func TestClientDIEventEmission(t *testing.T) {
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

	// Test that DI events can be emitted from client code
	wg.Add(1)
	EmitDIStarted(ctx)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()

	if len(events) != 1 {
		t.Errorf("Expected 1 event, got %d", len(events))
		return
	}

	if events[0].Type != EventTypeDIStarted {
		t.Errorf("Expected DI started event, got %v", events[0].Type)
	}
}

func TestClientDICompletedEvent(t *testing.T) {
	defer UnregisterAllEventHandlers()

	var events []Event
	var mu sync.Mutex
	var wg sync.WaitGroup

	RegisterEventHandler(EventHandlerFunc(func(ctx context.Context, event Event) {
		mu.Lock()
		events = append(events, event)
		mu.Unlock()
		wg.Done()
	}))

	ctx := context.Background()
	guid := protocol.GUID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

	wg.Add(1)
	EmitDICompleted(ctx, guid, "test-device-info")
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()

	if len(events) != 1 {
		t.Errorf("Expected 1 event, got %d", len(events))
		return
	}

	if events[0].Type != EventTypeDICompleted {
		t.Errorf("Expected DI completed event, got %v", events[0].Type)
	}

	if events[0].GUID == nil {
		t.Error("Expected GUID to be set")
	} else if *events[0].GUID != guid {
		t.Errorf("Expected GUID %x, got %x", guid, *events[0].GUID)
	}

	if data, ok := events[0].Data.(DIEventData); ok {
		if data.DeviceInfo != "test-device-info" {
			t.Errorf("Expected device info 'test-device-info', got '%s'", data.DeviceInfo)
		}
	} else {
		t.Error("Expected DIEventData in event data")
	}
}

func TestClientDIFailedEvent(t *testing.T) {
	defer UnregisterAllEventHandlers()

	var events []Event
	var mu sync.Mutex
	var wg sync.WaitGroup

	RegisterEventHandler(EventHandlerFunc(func(ctx context.Context, event Event) {
		mu.Lock()
		events = append(events, event)
		mu.Unlock()
		wg.Done()
	}))

	ctx := context.Background()
	testError := &testError{msg: "test DI failure"}

	wg.Add(1)
	EmitDIFailed(ctx, testError)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()

	if len(events) != 1 {
		t.Errorf("Expected 1 event, got %d", len(events))
		return
	}

	if events[0].Type != EventTypeDIFailed {
		t.Errorf("Expected DI failed event, got %v", events[0].Type)
	}

	if events[0].Error == nil {
		t.Error("Expected error to be set")
	} else if events[0].Error.Error() != "test DI failure" {
		t.Errorf("Expected error 'test DI failure', got '%v'", events[0].Error)
	}
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}
