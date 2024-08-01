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
	"sync"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// PluginOwnerModule adapts an executable plugin to the internal module
// interface.
type PluginOwnerModule struct {
	Plugin

	once  sync.Once
	proto *pluginProtocol
	name  string
	err   error
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
		w, r, err := m.Start()
		if err != nil {
			m.err = err
			return
		}
		m.proto = &pluginProtocol{in: w, out: bufio.NewScanner(r)}

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
