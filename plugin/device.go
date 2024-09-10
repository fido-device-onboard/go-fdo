// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package plugin

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// DeviceModule adapts an executable plugin to the internal module interface.
type DeviceModule struct {
	Module

	once  sync.Once
	proto *protocol
	name  string
	err   error
}

var _ serviceinfo.DeviceModule = (*DeviceModule)(nil)

// Transition implements serviceinfo.DeviceModule.
func (m *DeviceModule) Transition(active bool) error { return nil }

// Receive implements serviceinfo.DeviceModule.
func (m *DeviceModule) Receive(ctx context.Context, messageName string, messageBody io.Reader, respond func(message string) io.Writer, yield func()) error {
	m.once.Do(m.start)
	if m.err != nil {
		return m.err
	}

	name := m.name + ":" + messageName

	// Decode CBOR and encode to plugin protocol
	var val interface{}
	if err := cbor.NewDecoder(messageBody).Decode(&val); err != nil {
		return fmt.Errorf("error decoding message %q body: %w", name, err)
	}
	if err := m.proto.Send(dKey, messageName); err != nil {
		return fmt.Errorf("error sending message %q to plugin: %w", name, err)
	}
	if err := m.proto.EncodeValue(val); err != nil {
		return fmt.Errorf("error encoding message %q body: %w", name, err)
	}

	return nil
}

// Yield implements serviceinfo.DeviceModule.
func (m *DeviceModule) Yield(ctx context.Context, respond func(message string) io.Writer, yield func()) error {
	m.once.Do(m.start)
	if m.err != nil {
		return m.err
	}

	// Send yield to plugin
	if err := m.proto.Send(dYield, nil); err != nil {
		return err
	}

	// Read messages until plugin yields
	for {
		c, param, err := m.proto.Recv()
		if err != nil {
			return err
		}

		switch c {
		case dYield:
			return nil

		case dBreak:
			yield()

		case dKey:
			message := param.(string)
			w := respond(message)

			val, err := m.proto.DecodeValue()
			if err != nil {
				return err
			}
			if err := cbor.NewEncoder(w).Encode(val); err != nil {
				return err
			}

		default:
			return fmt.Errorf("invalid data: got unexpected command %q while parsing", c)
		}
	}
}

func (m *DeviceModule) start() {
	w, r, err := m.Start()
	if err != nil {
		m.err = err
		return
	}

	proto := &protocol{in: w, out: bufio.NewScanner(r)}
	name, err := proto.ModuleName()
	if err != nil {
		m.err = err
		return
	}

	m.proto, m.name = proto, name
}

// Stop calls the Stop method of the underlying plugin.Module. It also makes
// sure that the next Yield/Receive will start the plugin again.
func (m *DeviceModule) Stop() error {
	defer func() { m.once = sync.Once{} }()
	return m.Module.Stop()
}
