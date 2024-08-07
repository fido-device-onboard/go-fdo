// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package serviceinfo

import (
	"context"
	"io"
)

// OwnerModule implements a service info module.
type OwnerModule interface {
	// HandleInfo is called once for each service info KV received from the
	// device.
	HandleInfo(ctx context.Context, moduleName, messageName string, messageBody io.Reader) error

	// ProduceInfo is called once for each TO2.DeviceServiceInfo, after
	// HandleInfo is called for each service info KV, unless the device
	// indicated IsMoreServiceInfo.
	//
	// If `blockPeer` is true, the owner service will indicate
	// IsMoreServiceInfo to keep the device from sending service info in the
	// next exchange. If `moduleDone` is true, then IsMoreServiceInfo will not
	// be set true, regardless of the value of `more`, and this module will no
	// longer be used in the TO2 protocol.
	ProduceInfo(ctx context.Context, producer *Producer) (blockPeer, moduleDone bool, _ error)
}

// Producer allows an owner service info module to produce service info either
// with auto-chunking (not yet implemented) or manually.
type Producer struct {
	mtu  uint16
	info []*KV
}

// NewProducer creates a new producer instance for the given MTU.
func NewProducer(mtu uint16) *Producer {
	return &Producer{
		// 3 bytes are used by the CBOR message:
		//
		//   - 1 byte for "array of 3"
		//   - 1 byte for IsMoreServiceInfo boolean
		//   - 1 byte for IsDone boolean
		mtu: mtu - 3,
	}
}

// Available returns the remaining space available for a message body in bytes.
// If the next service info will not fit in the remaining bytes, then the
// module should return and on the next ProduceInfo the full MTU will be
// available.
func (p *Producer) Available(moduleName, messageName string) int {
	return int(p.mtu) - int(ArraySizeCBOR(append(p.info, &KV{Key: moduleName + ":" + messageName}))) +
		1 // 1 represents overcounting the size of the last KV, because the Val will be 1 byte
}

// WriteChunk queues a single service info. If messageBody is larger than the
// bytes available, WriteChunk will fail and no service info will be queued.
func (p *Producer) WriteChunk(moduleName, messageName string, messageBody []byte) error {
	p.info = append(p.info, &KV{
		Key: moduleName + ":" + messageName,
		Val: messageBody,
	})
	return nil
}

// AutoChunk writes one or more service info. When the MTU is exceeded...
// TODO: How to queue unsent service info chunks? What about non-affinity?
//
// func (p *Producer) AutoChunk(moduleName, messageName string) io.Writer

// ServiceInfo returns all ServiceInfo, guaranteed to fit within the MTU.
func (p *Producer) ServiceInfo() []*KV { return p.info }
