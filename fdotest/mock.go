// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package fdotest contains test harnesses for the main fdo package.
package fdotest

import (
	"context"
	"io"

	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// MockDeviceModule implements a trivial serviceinfo.DeviceModule.
type MockDeviceModule struct{}

var _ serviceinfo.DeviceModule = (*MockDeviceModule)(nil)

// Transition implements serviceinfo.DeviceModule.
func (m *MockDeviceModule) Transition(active bool) error { return nil }

// Receive implements serviceinfo.DeviceModule.
func (m *MockDeviceModule) Receive(ctx context.Context, moduleName, messageName string, messageBody io.Reader, respond func(message string) io.Writer, yield func()) error {
	return nil
}

// Yield implements serviceinfo.DeviceModule.
func (m *MockDeviceModule) Yield(ctx context.Context, respond func(message string) io.Writer, yield func()) error {
	return nil
}

// MockOwnerModule implements a trivial serviceinfo.OwnerModule.
type MockOwnerModule struct{}

var _ serviceinfo.OwnerModule = (*MockOwnerModule)(nil)

// HandleInfo implements serviceinfo.OwnerModule.
func (m *MockOwnerModule) HandleInfo(ctx context.Context, moduleName, messageName string, messageBody io.Reader) error {
	return nil
}

// ProduceInfo implements serviceinfo.OwnerModule.
func (m *MockOwnerModule) ProduceInfo(ctx context.Context, lastDeviceInfoEmpty bool, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	return false, true, nil
}
