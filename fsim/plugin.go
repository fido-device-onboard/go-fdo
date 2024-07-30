// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// PluginName returns the module name of a plugin.
func PluginName(cmd *exec.Cmd) (string, error) {
	in, err := cmd.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("error opening stdin pipe to plugin executable: %w", err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("error opening stdout pipe to plugin executable: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("error starting plugin executable: %w", err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	return (&pluginProtocol{in: in, out: bufio.NewScanner(out)}).ModuleName()
}

// PluginDeviceModule adapts an executable plugin to the internal module
// interface.
type PluginDeviceModule struct {
	// Start is required and is called when the module is activated to
	// initialize the plugin.
	Start func() (io.Writer, io.Reader, error)

	// Stop is optional and is called after all modules have been completed.
	Stop func() error

	// GracefulStop is optional and will be called before Stop. Stop will not
	// be called until at least the context provided has expired.
	GracefulStop func(context.Context) error

	once  sync.Once
	proto *pluginProtocol
	err   error
}

var _ serviceinfo.DeviceModule = (*PluginDeviceModule)(nil)

// NewPluginDeviceModuleFromCmd creates a device service info module from a
// lazily executed command.
func NewPluginDeviceModuleFromCmd(f func() *exec.Cmd) *PluginDeviceModule {
	var cmd *exec.Cmd
	return &PluginDeviceModule{
		Start: func() (io.Writer, io.Reader, error) {
			cmd = f()

			in, err := cmd.StdinPipe()
			if err != nil {
				return nil, nil, fmt.Errorf("error opening stdin pipe to plugin executable: %w", err)
			}
			out, err := cmd.StdoutPipe()
			if err != nil {
				return nil, nil, fmt.Errorf("error opening stdout pipe to plugin executable: %w", err)
			}

			if err := cmd.Start(); err != nil {
				return nil, nil, fmt.Errorf("error starting plugin executable: %w", err)
			}

			return in, out, nil
		},
		Stop: func() error {
			if cmd == nil {
				return nil
			}
			if err := cmd.Process.Kill(); err != nil {
				return err
			}
			return cmd.Wait()
		},
	}
}

// Transition implements serviceinfo.DeviceModule.
func (m *PluginDeviceModule) Transition(active bool) error {
	if !active {
		return nil
	}

	m.once.Do(func() {
		in, out, err := m.Start()
		if err != nil {
			m.err = err
			return
		}
		m.proto = &pluginProtocol{in: in, out: bufio.NewScanner(out)}
	})

	return m.err
}

// Receive implements serviceinfo.DeviceModule.
func (m *PluginDeviceModule) Receive(ctx context.Context, moduleName, messageName string, messageBody io.Reader, respond func(message string) io.Writer, yield func()) error {
	if m.proto == nil {
		return errors.New("plugin module not activated")
	}

	name := moduleName + ":" + messageName

	// Decode CBOR and encode to plugin protocol
	var val interface{}
	if err := cbor.NewDecoder(messageBody).Decode(&val); err != nil {
		return fmt.Errorf("error decoding message %q body: %w", name, err)
	}
	if err := m.proto.Send(dKey, base64.StdEncoding.EncodeToString([]byte(messageName))); err != nil {
		return fmt.Errorf("error sending message %q to plugin: %w", name, err)
	}
	if err := m.proto.EncodeValue(val); err != nil {
		return fmt.Errorf("error encoding message %q body: %w", name, err)
	}

	return nil
}

// Yield implements serviceinfo.DeviceModule.
func (m *PluginDeviceModule) Yield(ctx context.Context, respond func(message string) io.Writer, yield func()) error {
	if m.proto == nil {
		return errors.New("plugin module not activated")
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
			return nil

		case dKey:
			message := param.(string)
			w := respond(message)

			val, err := m.proto.DecodeValue()
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
	// Start is required and is called when the module is activated to
	// initialize the plugin.
	Start func() (io.Writer, io.Reader, error)

	// Stop is optional and is called after all modules have been completed.
	Stop func() error

	// GracefulStop is optional and will be called before Stop. Stop will not
	// be called until at least the context provided has expired.
	GracefulStop func(context.Context) error

	once  sync.Once
	proto *pluginProtocol
	name  string
	err   error
}

var _ serviceinfo.OwnerModule = (*PluginOwnerModule)(nil)

// NewPluginOwnerModuleFromCmd creates an owner service info module from a
// lazily executed command.
func NewPluginOwnerModuleFromCmd(f func() *exec.Cmd) *PluginOwnerModule {
	var cmd *exec.Cmd
	return &PluginOwnerModule{
		Start: func() (io.Writer, io.Reader, error) {
			cmd = f()

			in, err := cmd.StdinPipe()
			if err != nil {
				return nil, nil, fmt.Errorf("error opening stdin pipe to plugin executable: %w", err)
			}
			out, err := cmd.StdoutPipe()
			if err != nil {
				return nil, nil, fmt.Errorf("error opening stdout pipe to plugin executable: %w", err)
			}

			if err := cmd.Start(); err != nil {
				return nil, nil, fmt.Errorf("error starting plugin executable: %w", err)
			}

			return in, out, nil
		},
		Stop: func() error {
			if cmd == nil {
				return nil
			}
			if err := cmd.Process.Kill(); err != nil {
				return err
			}
			return cmd.Wait()
		},
	}
}

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
	if err := m.proto.Send(dKey, base64.StdEncoding.EncodeToString([]byte(messageName))); err != nil {
		return fmt.Errorf("error sending message %q key: %w", name, err)
	}
	if err := m.proto.EncodeValue(val); err != nil {
		return fmt.Errorf("error encoding message %q body: %w", name, err)
	}

	return nil
}

// ProduceInfo implements serviceinfo.OwnerModule.
func (m *PluginOwnerModule) ProduceInfo(ctx context.Context, lastDeviceInfoEmpty bool, producer *serviceinfo.Producer) (blockPeer, fsimDone bool, err error) {
	// Perform plugin startup sequence the first time
	m.once.Do(func() {
		in, out, err := m.Start()
		if err != nil {
			m.err = err
			return
		}
		m.proto = &pluginProtocol{in: in, out: bufio.NewScanner(out)}

		if m.name, m.err = m.proto.ModuleName(); m.err != nil {
			return
		}
	})
	if m.err != nil {
		return false, false, err
	}

	// Send a yield to let owner know it can start sending info
	if err := m.proto.Send(dYield, nil); err != nil {
		return false, false, err
	}

	// Read data commands from plugin until break, yield, or error and produce info
	for {
		c, param, err := m.proto.Recv()
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
			if err := m.decodeAndProduce(moduleName, messageName, producer); err != nil {
				return false, false, err
			}

		default:
			return false, false, fmt.Errorf("plugin produced message value [command=%q] before a message name", c)
		}
	}
}

func (m *PluginOwnerModule) decodeAndProduce(moduleName, messageName string, producer *serviceinfo.Producer) error {
	val, err := m.proto.DecodeValue()
	if err != nil {
		return err
	}

	messageBody, err := cbor.Marshal(val)
	if err != nil {
		return err
	}

	if len(messageBody) > producer.Available(moduleName, messageName) {
		return errors.New("plugin produced a message too large to send")
	}

	if err := producer.WriteChunk(moduleName, messageName, messageBody); err != nil {
		return err
	}

	return nil
}
