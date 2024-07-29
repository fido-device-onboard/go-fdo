// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"unicode/utf8"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// PluginName returns the module name of a plugin.
func PluginName(cmd *exec.Cmd) (string, error) {
	// Start plugin
	plug, err := newPlugin(cmd)
	if err != nil {
		return "", err
	}
	defer func() { _ = plug.Stop() }()

	return pluginModuleName(plug)
}

func pluginModuleName(plug *plugin) (string, error) {
	// Request and receive the module name
	if err := plug.Send(cModuleName, nil); err != nil {
		return "", fmt.Errorf("error sending module name command: %w", err)
	}
	c, val, err := plug.Recv()
	if c != cModuleName {
		return "", fmt.Errorf("plugin responded incorrectly to module name command: received %q command", c)
	}
	if err != nil {
		return "", fmt.Errorf("error receiving module name response: %w", err)
	}
	name := val.(string) // safe due to internal parsing in Recv()

	// Validate and return module name
	if !utf8.ValidString(name) {
		return "", fmt.Errorf("plugin returned a module name that was not valid UTF-8")
	}
	return string(name), nil
}

// PluginDeviceModule adapts an executable plugin to the internal module
// interface.
type PluginDeviceModule struct {
	Exec func() *exec.Cmd

	plug *plugin
}

var _ serviceinfo.DeviceModule = (*PluginDeviceModule)(nil)

// Transition implements serviceinfo.DeviceModule.
func (m *PluginDeviceModule) Transition(active bool) error {
	if !active {
		if m.plug == nil {
			return nil
		}
		return m.plug.Stop()
	}

	var err error
	m.plug, err = newPlugin(m.Exec())
	return err
}

// Receive implements serviceinfo.DeviceModule.
func (m *PluginDeviceModule) Receive(ctx context.Context, moduleName, messageName string, messageBody io.Reader, respond func(message string) io.Writer, yield func()) error {
	if m.plug == nil {
		return errors.New("plugin module not activated")
	}

	name := moduleName + ":" + messageName

	// Decode CBOR and encode to plugin protocol
	var val interface{}
	if err := cbor.NewDecoder(messageBody).Decode(&val); err != nil {
		return fmt.Errorf("error decoding message %q body: %w", name, err)
	}
	if err := m.plug.Send(dKey, base64.StdEncoding.EncodeToString([]byte(messageName))); err != nil {
		return fmt.Errorf("error sending message %q to plugin: %w", name, err)
	}
	if err := m.plug.EncodeValue(val); err != nil {
		return fmt.Errorf("error encoding message %q body: %w", name, err)
	}

	return nil
}

// Yield implements serviceinfo.DeviceModule.
func (m *PluginDeviceModule) Yield(ctx context.Context, respond func(message string) io.Writer, yield func()) error {
	if m.plug == nil {
		return errors.New("plugin module not activated")
	}

	// Send yield to plugin
	if err := m.plug.Send(dYield, nil); err != nil {
		return err
	}

	// Read messages until plugin yields
	for {
		c, param, err := m.plug.Recv()
		if err != nil {
			return err
		}

		switch c {
		case dYield:
			return nil

		case dBreak:
			yield()
			return nil

		case dKey:
			message := param.(string)
			w := respond(message)

			val, err := m.plug.DecodeValue()
			if err != nil {
				return err
			}
			return cbor.NewEncoder(w).Encode(val)

		default:
			return fmt.Errorf("invalid data: got unexpected command %q while parsing", c)
		}
	}
}

// PluginOwnerModule adapts an executable plugin to the internal module
// interface.
type PluginOwnerModule struct {
	Exec func() *exec.Cmd

	once sync.Once
	plug *plugin

	name string
}

var _ serviceinfo.OwnerModule = (*PluginOwnerModule)(nil)

// HandleInfo implements serviceinfo.OwnerModule.
//
// TODO: Allow plugin to declare maximum chunk size?
func (m *PluginOwnerModule) HandleInfo(ctx context.Context, moduleName, messageName string, messageBody io.Reader) error {
	name := moduleName + ":" + messageName

	// Decode CBOR and encode to plugin protocol
	var val interface{}
	if err := cbor.NewDecoder(messageBody).Decode(&val); err != nil {
		return fmt.Errorf("error decoding message %q body: %w", name, err)
	}
	if err := m.plug.Send(dKey, base64.StdEncoding.EncodeToString([]byte(messageName))); err != nil {
		return fmt.Errorf("error sending message %q key: %w", name, err)
	}
	if err := m.plug.EncodeValue(val); err != nil {
		return fmt.Errorf("error encoding message %q body: %w", name, err)
	}

	return nil
}

// ProduceInfo implements serviceinfo.OwnerModule.
func (m *PluginOwnerModule) ProduceInfo(ctx context.Context, lastDeviceInfoEmpty bool, producer *serviceinfo.Producer) (blockPeer, fsimDone bool, err error) {
	// Perform plugin startup sequence the first time
	m.once.Do(func() {
		m.plug, err = newPlugin(m.Exec())
		if err != nil {
			m.name, err = pluginModuleName(m.plug)
		}
	})
	if err != nil {
		return false, false, err
	}

	// Send a yield to let owner know it can start sending info
	if err := m.plug.Send(dYield, nil); err != nil {
		return false, false, err
	}

	// Read data commands from plugin until break, yield, or error and produce info
	for {
		c, param, err := m.plug.Recv()
		if err != nil {
			return false, false, err
		}

		switch c {
		case dBreak:
			return true, false, nil
		case dYield:
			return false, false, nil
		case dDone:
			return false, true, nil
		case dError:
			return false, false, fmt.Errorf("plugin error: %s", param)

		case dKey:
			moduleName, messageName := m.name, param.(string)

			val, err := m.plug.DecodeValue()
			if err != nil {
				return false, false, err
			}

			messageBody, err := cbor.Marshal(val)
			if err != nil {
				return false, false, err
			}

			if len(messageBody) > producer.Available(moduleName, messageName) {
				return false, false, errors.New("plugin produced a message too large to send")
			}

			if err := producer.WriteChunk(moduleName, messageName, messageBody); err != nil {
				return false, false, err
			}

		default:
			return false, false, fmt.Errorf("plugin produced message value [command=%q] before a message name", c)
		}
	}
}

// TODO: Implement GracefulStop

// Stop ungracefully kills the plugin executable.
func (m *PluginOwnerModule) Stop() error {
	if m.plug == nil {
		return nil
	}
	return m.plug.Stop()
}
