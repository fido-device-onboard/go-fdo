// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package fdotest contains test harnesses for the main fdo package.
package fdotest

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/fido-device-onboard/go-fdo/plugin"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// MockDeviceModule implements a trivial serviceinfo.DeviceModule.
type MockDeviceModule struct {
	ActiveState    bool
	TransitionFunc func(active bool) error
	ReceiveFunc    func(ctx context.Context, messageName string, messageBody io.Reader, respond func(message string) io.Writer, yield func()) error
	YieldFunc      func(ctx context.Context, respond func(message string) io.Writer, yield func()) error
}

var _ serviceinfo.DeviceModule = (*MockDeviceModule)(nil)

// Transition implements serviceinfo.DeviceModule.
func (m *MockDeviceModule) Transition(active bool) error {
	m.ActiveState = active
	if m.TransitionFunc != nil {
		return m.TransitionFunc(active)
	}
	return nil
}

// Receive implements serviceinfo.DeviceModule.
func (m *MockDeviceModule) Receive(ctx context.Context, messageName string, messageBody io.Reader, respond func(message string) io.Writer, yield func()) error {
	if m.ReceiveFunc != nil {
		return m.ReceiveFunc(ctx, messageName, messageBody, respond, yield)
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
	HandleInfoFunc  func(ctx context.Context, messageName string, messageBody io.Reader) error
	ProduceInfoFunc func(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error)
}

var _ serviceinfo.OwnerModule = (*MockOwnerModule)(nil)

// HandleInfo implements serviceinfo.OwnerModule.
func (m *MockOwnerModule) HandleInfo(ctx context.Context, messageName string, messageBody io.Reader) error {
	if m.HandleInfoFunc != nil {
		return m.HandleInfoFunc(ctx, messageName, messageBody)
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
	Routines         func() (func(context.Context, io.Writer) error, func(context.Context, io.Reader) error)
	Stopped          chan struct{}
	GracefulStopped  chan struct{}
	GracefulStopFunc func(context.Context) error

	cancel context.CancelFunc
	errc   <-chan error
}

var _ plugin.Module = (*MockPlugin)(nil)

// Start implements plugin.Module.
func (m *MockPlugin) Start() (io.Writer, io.Reader, error) {
	if m.Routines == nil {
		return nil, nil, errors.New("plugin routines not provided to mock")
	}
	writeRoutine, readRoutine := m.Routines()

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		wg.Wait()
		close(errc)
	}()

	rIn, wIn := io.Pipe()
	go func() {
		defer wg.Done()

		if err := readRoutine(ctx, rIn); err != nil {
			cancel()

			select {
			case errc <- err:
			default:
			}
		}
	}()

	rOut, wOut := io.Pipe()
	go func() {
		defer wg.Done()

		if err := writeRoutine(ctx, wOut); err != nil {
			cancel()

			select {
			case errc <- err:
			default:
			}
		}
	}()

	m.cancel = cancel
	m.errc = errc
	m.Stopped = make(chan struct{})
	m.GracefulStopped = make(chan struct{})
	return wIn, rOut, nil
}

// Stop implements plugin.Module.
func (m *MockPlugin) Stop() error {
	if m.cancel == nil {
		panic("stop called before start")
	}
	defer close(m.Stopped)

	m.cancel()

	return <-m.errc
}

// GracefulStop implements plugin.Module.
func (m *MockPlugin) GracefulStop(ctx context.Context) error {
	if m.cancel == nil {
		panic("stop called before start")
	}
	defer close(m.GracefulStopped)

	m.cancel()

	if m.GracefulStopFunc != nil {
		return m.GracefulStopFunc(ctx)
	}
	return nil
}

// ModuleNameOnlyRoutines creates routines that only respond to module name
// commands.
func ModuleNameOnlyRoutines(moduleName string) func() (func(context.Context, io.Writer) error, func(context.Context, io.Reader) error) {
	return func() (func(context.Context, io.Writer) error, func(context.Context, io.Reader) error) {
		gotModuleNameCommand := make(chan struct{})

		return func(ctx context.Context, w io.Writer) error {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-gotModuleNameCommand:
				}

				name := base64.StdEncoding.EncodeToString([]byte(moduleName))
				if _, err := w.Write(append([]byte{'M'}, name...)); err != nil {
					return err
				}
				if _, err := w.Write([]byte{'\n'}); err != nil {
					return err
				}

				return nil
			}, func(ctx context.Context, r io.Reader) error {
				scanner := bufio.NewScanner(r)
				if !scanner.Scan() {
					if err := scanner.Err(); err != nil {
						return err
					}
					return io.ErrUnexpectedEOF
				}

				if scanner.Text() != "M" {
					return fmt.Errorf("expected module name command")
				}

				close(gotModuleNameCommand)
				return nil
			}
	}
}
