// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package main provides an example of using FDO DI event callbacks
package main

import (
	"context"
	"fmt"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

func main() {
	// Register an event handler to track DI events
	fdo.RegisterEventHandler(fdo.EventHandlerFunc(func(ctx context.Context, event fdo.Event) {
		switch event.Type {
		case fdo.EventTypeDIStarted:
			fmt.Printf("🚀 DI Started: Device beginning initialization\n")

		case fdo.EventTypeDICompleted:
			if event.GUID != nil {
				fmt.Printf("✅ DI Completed: Device %x successfully initialized\n", *event.GUID)

				// Access device info if available
				if data, ok := event.Data.(fdo.DIEventData); ok {
					fmt.Printf("   Device Info: %s\n", data.DeviceInfo)
				}
			}

		case fdo.EventTypeDIFailed:
			if event.Error != nil {
				fmt.Printf("❌ DI Failed: %v\n", event.Error)
			}
		}
	}))

	// Example: Simulate DI events
	fmt.Println("=== FDO DI Event Example ===")

	ctx := context.Background()

	// Simulate DI started
	fdo.EmitDIStarted(ctx)

	// Simulate DI completed with a sample GUID
	guid := protocol.GUID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	fdo.EmitDICompleted(ctx, guid, "sample-device-info")

	// Simulate DI failed
	fdo.EmitDIFailed(ctx, fmt.Errorf("connection timeout"))

	// Wait for events to be processed
	fdo.FlushEvents()

	fmt.Println("=== Example Complete ===")
}
