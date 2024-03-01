// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// Buffer service info send and receive queues. This buffer may grow
// indefinitely if FSIMs are not well behaved. For example, if an owner service
// sends 100s of upload requests, the requests will be processed as they are
// received and may fill up the send buffer until the device is out of memory.
//
// While in this case, it may seem obvious that the upload requests should be
// buffered and then processed rather than handled sequentially, it would be
// equally unsafe to implement this behavior, because the request buffer may
// also grow past the MTU if IsMoreServiceInfo is used, keeping the device from
// processing its received service info.
//
// In the end, there's no general way to exchange arbitrary data between two
// parties where each piece of data one party receives may cause it to put any
// number of pieces of data on its send queue and the other party gets to
// choose when it may flush its queue.
//
// Buffering both queues and relying on good behavior of FSIMs is the best and
// only real option. Both queues should be buffered because there can be an
// asymmetric use of queues in either direction. Many file upload requests
// results in a small device receive queue and large device send queue. Many
// file downloads result in the opposite.

func handleFSIMs(ctx context.Context, modules fsimMap, ownerInfo *serviceinfo.UnchunkReader, deviceInfoChan chan<- *serviceinfo.ChunkReader) {
	defer close(deviceInfoChan)

	// 1000 service info buffered in and out means up to ~1MB of data for
	// the default MTU. If both queues fill, the device will deadlock. This
	// should only happen for a poorly behaved FSIM.
	deviceInfo, send := serviceinfo.NewChunkOutPipe(1000)
	select {
	case <-ctx.Done():
		return
	case deviceInfoChan <- deviceInfo:
	}

	for {
		// Get next service info from the owner service and handle it.
		key, messageBody, ok := ownerInfo.NextServiceInfo()
		fmt.Println(key, ok)
		if !ok {
			_ = send.Close()
			return
		}
		moduleName, messageName, _ := strings.Cut(key, ":")

		// Automatically receive and respond to active messages. This send is
		// expected to be buffered until all receives are processed, unlike
		// modules which must wait for all receives to occur before sending.
		// This is allowed because the data is small and the send buffer is
		// large enough for many more "active" responses than is practical to
		// expect in the real world.
		fsim, active := modules.Lookup(moduleName)
		if messageName == "active" {
			newActive, err := handleActive(active, fsim, moduleName, messageBody, send)
			if err != nil {
				_ = send.CloseWithError(err)
				return
			}
			modules.active[moduleName] = newActive
			continue
		}
		if !active {
			continue
		}

		// Use FSIM handler and provide it a function which can be used to send
		// zero or more service info KVs. The function returns a writer to
		// write the value part of the service info KV.
		//
		// If the FSIM handler returns an error then the pipe will be closed
		// with an error, causing the error to propagate to the chunk reader,
		// which is used in the ServiceInfo send loop.
		if err := handleFSIM(ctx, fsim, moduleName, messageName, messageBody, send); err != nil {
			_ = send.CloseWithError(err)
			return
		}
	}
}

func handleActive(prevActive bool, fsim serviceinfo.DeviceModule, moduleName string, messageBody io.Reader, send *serviceinfo.UnchunkWriter) (bool, error) {
	// Receive active message of true or false
	var active bool
	if err := cbor.NewDecoder(messageBody).Decode(&active); err != nil {
		return false, err
	}
	// Check err after getting sender
	_, _ = io.Copy(io.Discard, messageBody)

	// Transition internal state
	if active != prevActive {
		if err := fsim.Transition(active); err != nil {
			return false, err
		}
	}

	// Send active message when appropriate
	if !active || prevActive {
		return active, nil
	}
	if _, isUnknown := fsim.(serviceinfo.UnknownModule); isUnknown && moduleName != devmodModuleName {
		active = false
	}
	if err := send.NextServiceInfo(moduleName, "active"); err != nil {
		return false, err
	}
	if err := cbor.NewEncoder(send).Encode(active); err != nil {
		return false, err
	}
	return active, nil
}

func handleFSIM(ctx context.Context, fsim serviceinfo.DeviceModule, moduleName, messageName string, messageBody io.Reader, send *serviceinfo.UnchunkWriter) error {
	// Construct respond/yield callback functions
	respond := func(messageName string) io.Writer {
		_ = send.NextServiceInfo(moduleName, messageName)
		return send
	}
	yield := func() {
		_ = send.ForceNewMessage()
	}

	// Handle message
	if err := fsim.Receive(ctx, moduleName, messageName, messageBody, respond, yield); err != nil {
		return err
	}

	// Ensure that buffer was drained, even if an unsafe module was used
	if n, err := io.Copy(io.Discard, messageBody); err != nil {
		return err
	} else if n > 0 {
		return fmt.Errorf(
			"fsim did not read full body of message '%s:%s'",
			moduleName, messageName)
	}
	return nil
}

type fsimMap struct {
	modules map[string]serviceinfo.DeviceModule
	active  map[string]bool
}

func (fm fsimMap) Lookup(moduleName string) (fsim serviceinfo.DeviceModule, active bool) {
	module, known := fm.modules[moduleName]
	if !known {
		module = serviceinfo.UnknownModule{}
	}
	return module, fm.active[moduleName]
}
