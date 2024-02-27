// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// Handle owner service info with FSIMs. This must be run in a goroutine,
// because the chunking/unchunking pipes are not buffered.
func handleFSIMs(ctx context.Context, mtu uint16, modules fsimMap, send *serviceinfo.UnchunkWriter, recv *serviceinfo.UnchunkReader) {
	var writeChans []chan chan struct{}
	for {
		// Get next service info from the owner service and handle it.
		key, messageBody, ok := recv.NextServiceInfo()
		if !ok {
			_ = send.Close()
			break
		}

		// Automatically receive and respond to active messages. This send is
		// expected to be buffered until all receives are processed, unlike
		// modules which must wait for all receives to occur before sending.
		// This is allowed because the data is small and the send buffer is
		// large enough for many more "active" responses than is practical to
		// expect in the real world.
		moduleName, messageName, _ := strings.Cut(key, ":")
		fsim, active := modules.Lookup(moduleName)
		if messageName == "active" {
			// Receive active message of true or false
			prevActive, active := active, false
			if err := cbor.NewDecoder(messageBody).Decode(&active); err != nil {
				_ = send.CloseWithError(err)
				return
			}
			_, _ = io.Copy(io.Discard, messageBody)

			// Transition internal state
			modules.active[moduleName] = active
			fsim.Transition(active)

			// Send active message when appropriate
			if active && !prevActive {
				if err := sendActive(moduleName, active, fsim, send); err != nil {
					_ = send.CloseWithError(err)
					return
				}
			}
			continue
		}

		// Use FSIM handler and provide it a function which can be used to send
		// zero or more service info KVs. The function returns a writer to
		// write the value part of the service info KV. This writer is buffered
		// and automatically flushed when the handler returns or another
		// service info is to be sent.
		//
		// If the FSIM handler returns an error then the pipe will be closed
		// with an error, causing the error to propagate to the chunk reader,
		// which is used in the ServiceInfo send loop.
		//
		// The FSIM is handled in a goroutine, allowing service info to be read
		// and processed in parallel, but sends are serialized via a channel
		// letting it know when to start and indicate back when writing is
		// complete.
		readyToWrite := make(chan chan struct{})
		writeChans = append(writeChans, readyToWrite)
		go handleFSIM(ctx, fsim, moduleName, messageName, messageBody, send, mtu, readyToWrite)
	}

	// Synchronize writes by sending one done channel at a time and waiting for
	// the receiver to send back done.
	for _, nextWrite := range writeChans {
		done := make(chan struct{})
		select {
		case <-ctx.Done():
			return
		case nextWrite <- done:
		}
		select {
		case <-ctx.Done():
			return
		case <-done:
		}
	}
}

func sendActive(moduleName string, active bool, fsim serviceinfo.DeviceModule, send *serviceinfo.UnchunkWriter) error {
	if _, isUnknown := fsim.(serviceinfo.UnknownModule); isUnknown && moduleName != devmodModuleName {
		active = false
	}
	if err := send.NextServiceInfo(moduleName, "active"); err != nil {
		return err
	}
	if err := cbor.NewEncoder(send).Encode(active); err != nil {
		return err
	}
	return nil
}

func handleFSIM(ctx context.Context, fsim serviceinfo.DeviceModule,
	moduleName, messageName string, messageBody io.Reader,
	send *serviceinfo.UnchunkWriter, mtu uint16, readyToWrite <-chan chan struct{},
) {
	var done chan<- struct{}
	defer func() {
		if done != nil {
			close(done)
		}
	}()
	buf := bufio.NewWriterSize(send, int(mtu))
	if err := fsim.Receive(ctx, moduleName, messageName, messageBody, func(messageName string) io.Writer {
		_ = buf.Flush()
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

		// Wait on channel to synchronize response order
		select {
		case <-ctx.Done():
			_ = send.CloseWithError(ctx.Err())
			return send
		case done = <-readyToWrite:
		}

		_ = send.NextServiceInfo(moduleName, messageName)
		return buf
	}); err != nil {
		_ = send.CloseWithError(err)
		return
	}
	if err := buf.Flush(); err != nil {
		_ = send.CloseWithError(err)
		return
	}

	// Ensure that buffer was drained, even if an unsafe module was used
	if n, err := io.Copy(io.Discard, messageBody); err != nil {
		_ = send.CloseWithError(err)
		return
	} else if n > 0 {
		_ = send.CloseWithError(fmt.Errorf(
			"fsim did not read full body of message '%s:%s'",
			moduleName, messageName))
		return
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
