// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"syscall"
	"time"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

const defaultCommandTimeout = time.Hour

// Command implements https://github.com/fido-alliance/fdo-sim/blob/main/fsim-repository/fdo.command.md
// and should be registered to the "fdo.command" module.
type Command struct {
	// Timeout determines the maximum amount of time to allow running the
	// command. Exceeding this time will result in the module sending an error.
	// If Timeout is zero, then a default of 1 hour will be used.
	Timeout time.Duration

	// Transform, if set, modifies a command and arguments before executing
	// them.
	Transform func(name string, arg []string) (newName string, newArg []string)

	// Message data
	arg0    string
	args    cbor.Bstr[[]string]
	mayFail bool
	stdout  bool
	stderr  bool

	// Internal state
	cmd  *exec.Cmd
	out  *bytes.Buffer
	err  *bytes.Buffer
	errc chan error
}

var _ serviceinfo.DeviceModule = (*Command)(nil)

// Transition implements serviceinfo.DeviceModule.
func (c *Command) Transition(active bool) error {
	if !active {
		c.reset()
	}
	return nil
}

// Receive implements serviceinfo.DeviceModule.
func (c *Command) Receive(ctx context.Context, messageName string, messageBody io.Reader, respond func(string) io.Writer, yield func()) error {
	if err := c.receive(ctx, messageName, messageBody); err != nil {
		c.reset()
		return err
	}
	return nil
}

func (c *Command) receive(ctx context.Context, messageName string, messageBody io.Reader) error {
	switch messageName {
	case "command":
		c.reset()
		return cbor.NewDecoder(messageBody).Decode(&c.arg0)

	case "args":
		return cbor.NewDecoder(messageBody).Decode(&c.args)

	case "may_fail":
		return cbor.NewDecoder(messageBody).Decode(&c.mayFail)

	case "return_stdout":
		return cbor.NewDecoder(messageBody).Decode(&c.stdout)

	case "return_stderr":
		return cbor.NewDecoder(messageBody).Decode(&c.stderr)

	case "execute":
		var empty struct{}
		if err := cbor.NewDecoder(messageBody).Decode(&empty); err != nil {
			return err
		}
		if c.cmd != nil {
			return fmt.Errorf("received execute twice")
		}
		return c.execute(ctx)

	case "sig":
		var sig syscall.Signal
		if err := cbor.NewDecoder(messageBody).Decode(&sig); err != nil {
			return err
		}
		if c.cmd == nil {
			return fmt.Errorf("received a signal before execute")
		}
		if c.cmd.Process == nil {
			panic("command should always be started")
		}
		return c.cmd.Process.Signal(sig)

	default:
		return fmt.Errorf("unknown message %s", messageName)
	}
}

func (c *Command) execute(ctx context.Context) error {
	name, arg := c.arg0, c.args.Val
	if name == "" {
		return fmt.Errorf("no command was given to execute")
	}
	if c.Transform != nil {
		name, arg = c.Transform(name, arg)
	}

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = defaultCommandTimeout
	}

	// Start command
	ctx, _ = context.WithTimeout(ctx, timeout)     //nolint:govet // This context is only used for the command
	c.cmd = exec.CommandContext(ctx, name, arg...) //nolint:gosec // This is dangerous by intentional design as the owner service is meant to be privileged
	if c.stdout {
		var buf bytes.Buffer
		c.cmd.Stdout = &buf
		c.out = &buf
	}
	if c.stderr {
		var buf bytes.Buffer
		c.cmd.Stderr = &buf
		c.err = &buf
	}
	if debugEnabled() {
		slog.Debug("fdo.command", "args", c.cmd.Args)
	}
	if err := c.cmd.Start(); err != nil {
		return fmt.Errorf("error starting command %v: %w", c.cmd.Args, err)
	}
	c.errc = make(chan error, 1)
	go func() {
		defer close(c.errc)
		if err := c.cmd.Wait(); err != nil {
			c.errc <- err
		}
	}()

	return nil
}

// Yield implements serviceinfo.DeviceModule.
func (c *Command) Yield(ctx context.Context, respond func(message string) io.Writer, yield func()) error {
	if c.cmd == nil {
		return nil
	}

	// Check exited before writing any output to avoid race conditions where
	// output is lost if process exits between writing stdout/stderr and the
	// exited check
	exited := c.cmd.ProcessState != nil

	// Send any data on the stdout/stderr pipes
	if c.stdout {
		if err := cborEncodeBuffer(respond("stdout"), c.out); err != nil {
			return fmt.Errorf("stderr: %w", err)
		}
	}
	if c.stderr {
		if err := cborEncodeBuffer(respond("stderr"), c.err); err != nil {
			return fmt.Errorf("stderr: %w", err)
		}
	}

	// Continue if process is still running
	if !exited {
		return nil
	}

	// Handle process exit
	defer c.reset()

	if err := <-c.errc; err != nil {
		return fmt.Errorf("command failed to execute: %w", err)
	}
	code := c.cmd.ProcessState.ExitCode()
	if code != 0 && !c.mayFail {
		return fmt.Errorf("command failed with exit code: %d", code)
	}

	return cbor.NewEncoder(respond("exitcode")).Encode(code)
}

func cborEncodeBuffer(w io.Writer, r *bytes.Buffer) error {
	n := r.Len()
	if n == 0 {
		return nil
	}

	buf := make([]byte, n)
	if _, err := r.Read(buf); err != nil {
		return fmt.Errorf("error reading from buffer: %w", err)
	}

	if err := cbor.NewEncoder(w).Encode(buf); err != nil {
		return fmt.Errorf("error sending buffer: %w", err)
	}

	return nil
}

func (c *Command) reset() {
	if c.cmd != nil {
		if c.cmd.Process == nil {
			panic("command should always be started")
		}
		_ = c.cmd.Process.Kill()
	}
	*c = Command{
		Timeout:   c.Timeout,
		Transform: c.Transform,
	}
}
