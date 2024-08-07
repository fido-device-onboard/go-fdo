// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package fdotest contains test harnesses for the main fdo package.
package fdotest

import (
	"context"
	"io"

	"github.com/fido-device-onboard/go-fdo/plugin"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// MockDeviceModule implements a trivial serviceinfo.DeviceModule.
type MockDeviceModule struct {
	ActiveState bool
	ReceiveFunc func(ctx context.Context, moduleName, messageName string, messageBody io.Reader, respond func(message string) io.Writer, yield func()) error
	YieldFunc   func(ctx context.Context, respond func(message string) io.Writer, yield func()) error
}

var _ serviceinfo.DeviceModule = (*MockDeviceModule)(nil)

// Transition implements serviceinfo.DeviceModule.
func (m *MockDeviceModule) Transition(active bool) error {
	m.ActiveState = active
	return nil
}

// Receive implements serviceinfo.DeviceModule.
func (m *MockDeviceModule) Receive(ctx context.Context, moduleName, messageName string, messageBody io.Reader, respond func(message string) io.Writer, yield func()) error {
	if m.ReceiveFunc != nil {
		return m.ReceiveFunc(ctx, moduleName, messageName, messageBody, respond, yield)
	}
	return nil
}

// Yield implements serviceinfo.DeviceModule.
func (m *MockDeviceModule) Yield(ctx context.Context, respond func(message string) io.Writer, yield func()) error {
	if m.YieldFunc != nil {
		return m.YieldFunc(ctx, respond, yield)
	}
	return nil
}

// MockOwnerModule implements a trivial serviceinfo.OwnerModule.
type MockOwnerModule struct {
	HandleInfoFunc  func(ctx context.Context, moduleName, messageName string, messageBody io.Reader) error
	ProduceInfoFunc func(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error)
}

var _ serviceinfo.OwnerModule = (*MockOwnerModule)(nil)

// HandleInfo implements serviceinfo.OwnerModule.
func (m *MockOwnerModule) HandleInfo(ctx context.Context, moduleName, messageName string, messageBody io.Reader) error {
	if m.HandleInfoFunc != nil {
		return m.HandleInfoFunc(ctx, moduleName, messageName, messageBody)
	}
	return nil
}

// ProduceInfo implements serviceinfo.OwnerModule.
func (m *MockOwnerModule) ProduceInfo(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	if m.ProduceInfoFunc != nil {
		return m.ProduceInfoFunc(ctx, producer)
	}
	return false, true, nil
}

// MockPlugin implements a trivial plugin.Module.
type MockPlugin struct {
	Stopped          bool
	GracefulStopped  bool
	GracefulStopFunc func(context.Context) error
}

var _ plugin.Module = (*MockPlugin)(nil)

// Start implements plugin.Module.
func (m *MockPlugin) Start() (io.Writer, io.Reader, error) { panic("unimplemented") }

// Stop implements plugin.Module.
func (m *MockPlugin) Stop() error {
	m.Stopped = true
	return nil
}

// GracefulStop implements plugin.Module.
func (m *MockPlugin) GracefulStop(ctx context.Context) error {
	defer func() { m.GracefulStopped = true }()
	if m.GracefulStopFunc != nil {
		return m.GracefulStopFunc(ctx)
	}
	return nil
}
