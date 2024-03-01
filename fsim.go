// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

type deviceFSIMSender struct {
	Chan chan *serviceinfo.UnchunkWriter
	Done chan struct{}
}

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

	var senders []deviceFSIMSender
	for {
		// Get next service info from the owner service and handle it.
		key, messageBody, ok := ownerInfo.NextServiceInfo()
		if !ok {
			break
		}
		moduleName, messageName, _ := strings.Cut(key, ":")

		// Prepare the next synchronized (ordered, one at a time) sender
		sender := deviceFSIMSender{
			Chan: make(chan *serviceinfo.UnchunkWriter),
			Done: make(chan struct{}),
		}
		senders = append(senders, sender)

		// Automatically receive and respond to active messages. This send is
		// expected to be buffered until all receives are processed, unlike
		// modules which must wait for all receives to occur before sending.
		// This is allowed because the data is small and the send buffer is
		// large enough for many more "active" responses than is practical to
		// expect in the real world.
		fsim, active := modules.Lookup(moduleName)
		if messageName == "active" {
			nextActive := make(chan bool, 1)
			go handleActive(ctx, active, nextActive, fsim, moduleName, messageBody, sender)
			modules.active[moduleName] = <-nextActive
			continue
		}
		if !active {
			close(sender.Done)
			continue
		}

		// Use FSIM handler and provide it a function which can be used to send
		// zero or more service info KVs. The function returns a writer to
		// write the value part of the service info KV.
		//
		// If the FSIM handler returns an error then the pipe will be closed
		// with an error, causing the error to propagate to the chunk reader,
		// which is used in the ServiceInfo send loop.
		//
		// The FSIM is handled in a goroutine, allowing service info to be read
		// and processed in parallel, but sends are serialized via a channel
		// letting it know when to start and indicate back when writing is
		// complete.
		//
		// TODO: Add a semaphore to limit the max number of goroutines spawned
		// at a given time?
		go handleFSIM(ctx, fsim, moduleName, messageName, messageBody, sender)
	}

	// Synchronize writes by sending one done channel at a time and waiting for
	// the receiver to send back done.
	for _, sender := range senders {
		_, prevSend := serviceinfo.NewChunkOutPipe(0)
		for {
			// 1000 service info buffered in and out means up to ~1MB of data for
			// the default MTU. If both queues fill, the device will deadlock. This
			// should only happen for a poorly behaved FSIM.
			deviceInfo, send := serviceinfo.NewChunkOutPipe(1000)

			select {
			case <-ctx.Done():
				_ = prevSend.CloseWithError(ctx.Err())
				return

			// Give the FSIM the current device info writer
			case sender.Chan <- send:
				_ = prevSend.Close()
				prevSend = send

				// Give the protocol back the device info reader
				select {
				case <-ctx.Done():
					return
				case deviceInfoChan <- deviceInfo:
				}

			// Sender may finish before needing another writer
			case <-sender.Done:
				_ = prevSend.Close()
				return
			}
		}
	}
}

func handleActive(ctx context.Context, prevActive bool, nextActive chan<- bool, fsim serviceinfo.DeviceModule, moduleName string, messageBody io.Reader, sender deviceFSIMSender) {
	defer close(sender.Done)

	// Receive active message of true or false
	var active bool
	err := cbor.NewDecoder(messageBody).Decode(&active)
	// Check err after getting sender
	_, _ = io.Copy(io.Discard, messageBody)
	nextActive <- active

	// Wait for writer to be ready
	var send *serviceinfo.UnchunkWriter
	select {
	case <-ctx.Done():
		return
	case send = <-sender.Chan:
	}
	if err != nil {
		_ = send.CloseWithError(err)
		return
	}

	// Transition internal state
	if active != prevActive {
		if err := fsim.Transition(active); err != nil {
			_ = send.CloseWithError(err)
			return
		}
	}

	// Send active message when appropriate
	if !active || prevActive {
		return
	}
	if _, isUnknown := fsim.(serviceinfo.UnknownModule); isUnknown && moduleName != devmodModuleName {
		active = false
	}
	if err := send.NextServiceInfo(moduleName, "active"); err != nil {
		_ = send.CloseWithError(err)
		return
	}
	if err := cbor.NewEncoder(send).Encode(active); err != nil {
		_ = send.CloseWithError(err)
		return
	}
}

func handleFSIM(ctx context.Context, fsim serviceinfo.DeviceModule,
	moduleName, messageName string, messageBody io.Reader, sender deviceFSIMSender) {
	defer close(sender.Done)

	// FIXME: Guarantee order
	respond, yield, send := respondFns(ctx, fsim, moduleName, messageBody, sender)
	if err := fsim.Receive(ctx, moduleName, messageName, messageBody, respond, yield); err != nil {
		_ = send().CloseWithError(err)
		return
	}

	// Ensure that buffer was drained, even if an unsafe module was used
	if n, err := io.Copy(io.Discard, messageBody); err != nil {
		_ = send().CloseWithError(err)
		return
	} else if n > 0 {
		_ = send().CloseWithError(fmt.Errorf(
			"fsim did not read full body of message '%s:%s'",
			moduleName, messageName))
		return
	}
}

func respondFns(ctx context.Context, fsim serviceinfo.DeviceModule, moduleName string, messageBody io.Reader, sender deviceFSIMSender) (
	func(string) io.Writer,
	func(),
	func() *serviceinfo.UnchunkWriter,
) {
	var send *serviceinfo.UnchunkWriter
	var once sync.Once
	init := func() {
		select {
		case <-ctx.Done():
			_, send = serviceinfo.NewChunkOutPipe(0)
		case send = <-sender.Chan:
		}
	}

	return func(messageName string) io.Writer {
			// Wait on channel to synchronize response order
			once.Do(init)
			select {
			case <-ctx.Done():
				_, send = serviceinfo.NewChunkOutPipe(0)
				_ = send.CloseWithError(ctx.Err())
				return send
			default:
			}

			// Drain messageBody and fail by closing writer with error if any
			// body remains. This is to ensure that writes occur only after
			// reads, thus allowing all service info to be read while response
			// writers wait to be signaled to start writing.
			if _, unsafe := fsim.(serviceinfo.UnsafeModule); !unsafe {
				if n, err := io.Copy(io.Discard, messageBody); err != nil {
					_ = send.CloseWithError(err)
					return send
				} else if n > 0 {
					_ = send.CloseWithError(fmt.Errorf(
						"fsim did not read full body of message '%s:%s'",
						moduleName, messageName))
					return send
				}
			}

			_ = send.NextServiceInfo(moduleName, messageName)
			return send
		}, func() {
			once.Do(init)
			_ = send.ForceNewMessage()
		}, func() *serviceinfo.UnchunkWriter {
			once.Do(init)
			return send
		}
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
