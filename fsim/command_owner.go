// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"context"
	"fmt"
	"io"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// Implement owner service info module for
// https://github.com/fido-alliance/fdo-sim/blob/main/fsim-repository/fdo.command.md

// RunCommand implements the fdo.command owner module.
type RunCommand struct {
	// Specifies the command processor to execute (e.g. sh , bash, or cmd )
	Command string

	// Command arguments
	Args []string

	// If false, Device will terminate TO2 on error (FDO message 255);
	// otherwise device will send exitcode and continue to process ServiceInfo.
	// This permits the Owner side to either take recovery action or fail the
	// connection (FDO message 255)
	MayFail bool

	// If set, stdout will be requested from the device and written to this
	// writer
	Stdout io.WriteCloser

	// If set, stderr will be requested from the device and written to this
	// writer
	Stderr io.WriteCloser

	// If set, the exit code will be sent on this channel. It should be
	// buffered with a size of 1.
	ExitChan chan<- int

	// Signals to send to command
	Signals <-chan int

	// Internal state
	sentCommand bool
	argBody     []byte
	sentExecute bool
	done        bool
}

var _ serviceinfo.OwnerModule = (*RunCommand)(nil)

// HandleInfo implements serviceinfo.OwnerModule.
func (c *RunCommand) HandleInfo(ctx context.Context, messageName string, messageBody io.Reader) error {
	if err := c.handleInfo(ctx, messageName, messageBody); err != nil {
		c.cleanup()
	}
	return nil
}

func (c *RunCommand) handleInfo(ctx context.Context, messageName string, messageBody io.Reader) error { //nolint:gocyclo // Message dispatch is best understood as a large switch stmt
	switch messageName {
	case "active":
		var deviceActive bool
		if err := cbor.NewDecoder(messageBody).Decode(&deviceActive); err != nil {
			return fmt.Errorf("error decoding message %s: %w", messageName, err)
		}
		if !deviceActive {
			return fmt.Errorf("device service info module is not active")
		}
		return nil

	case "stdout":
		var buf cbor.Bstr[[]byte]
		if err := cbor.NewDecoder(messageBody).Decode(&buf); err != nil {
			return fmt.Errorf("error decoding message %q: %w", messageName, err)
		}
		if c.Stdout == nil {
			return fmt.Errorf("stdout received but not requested")
		}
		if _, err := c.Stdout.Write(buf.Val); err != nil {
			return fmt.Errorf("error writing stdout: %w", err)
		}
		return nil

	case "stderr":
		var buf cbor.Bstr[[]byte]
		if err := cbor.NewDecoder(messageBody).Decode(&buf); err != nil {
			return fmt.Errorf("error decoding message %q: %w", messageName, err)
		}
		if c.Stderr == nil {
			return fmt.Errorf("stderr received but not requested")
		}
		if _, err := c.Stderr.Write(buf.Val); err != nil {
			return fmt.Errorf("error writing stderr: %w", err)
		}
		return nil

	case "exitcode":
		var code int
		if err := cbor.NewDecoder(messageBody).Decode(&code); err != nil {
			return fmt.Errorf("error decoding message %q: %w", messageName, err)
		}
		if c.ExitChan != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case c.ExitChan <- code:
			}
		}

		c.cleanup()
		c.done = true
		return nil

	default:
		return fmt.Errorf("unsupported message %q", messageName)
	}
}

// ProduceInfo implements serviceinfo.OwnerModule.
func (c *RunCommand) ProduceInfo(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	blockPeer, moduleDone, err := c.produceInfo(producer)
	if err != nil {
		c.cleanup()
	}
	return blockPeer, moduleDone, err
}

func (c *RunCommand) produceInfo(producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	if c.sentExecute {
		select {
		case sig := <-c.Signals:
			messageBody, err := cbor.Marshal(sig)
			if err != nil {
				return false, false, fmt.Errorf("error marshaling signal: %w", err)
			}
			if err := producer.WriteChunk("sig", messageBody); err != nil {
				return false, false, err
			}
		default:
			// No signals queued
		}

		return false, c.done, nil
	}

	if !c.sentCommand {
		cmdBody, err := cbor.Marshal(c.Command)
		if err != nil {
			return false, false, err
		}

		if err := producer.WriteChunk("active", []byte{0xf5}); err != nil {
			return false, false, err
		}
		if err := producer.WriteChunk("command", cmdBody); err != nil {
			return false, false, err
		}

		c.argBody, err = cbor.Marshal(*cbor.NewBstr(c.Args))
		if err != nil {
			return false, false, err
		}

		c.sentCommand = true
	}

	moreInfo, err := c.sendArgsAndExecute(producer)
	return moreInfo, false, err
}

func (c *RunCommand) sendArgsAndExecute(producer *serviceinfo.Producer) (moreInfo bool, _ error) {
	trueBody := []byte{0xf5}
	nullBody := []byte{0xf6}

	// Args may be long and require chunking
	remaining := producer.Available("args")
	if remaining < 1 {
		return true, nil
	}
	n := min(remaining, len(c.argBody))

	if n > 0 {
		var messageBody []byte
		messageBody, c.argBody = c.argBody[:n], c.argBody[n:]
		if err := producer.WriteChunk("args", messageBody); err != nil {
			return false, err
		}
	}

	// Send remaining messages
	if producer.Available("") < 100 { // ensure enough space after sending args
		return true, nil
	}
	if c.MayFail {
		if err := producer.WriteChunk("may_fail", trueBody); err != nil {
			return false, err
		}
	}
	if c.Stdout != nil {
		if err := producer.WriteChunk("return_stdout", trueBody); err != nil {
			return false, err
		}
	}
	if c.Stderr != nil {
		if err := producer.WriteChunk("return_stderr", trueBody); err != nil {
			return false, err
		}
	}
	if err := producer.WriteChunk("execute", nullBody); err != nil {
		return false, err
	}
	c.sentExecute = true

	return false, nil
}

func (c *RunCommand) cleanup() {
	if c.Stdout != nil {
		_ = c.Stdout.Close()
	}
	if c.Stderr != nil {
		_ = c.Stderr.Close()
	}
	if c.ExitChan != nil {
		close(c.ExitChan)
	}
}
