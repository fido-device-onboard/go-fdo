// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package plugin defines a line-based protocol and implements service info
// device and owner module adapters to plugins communicating over a reader-
// writer pair.
package plugin

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
)

// Module controls the generic start/stop behavior of the (usually OS
// executable) service info module plugin, whether an owner or device module.
type Module interface {
	// Start is called when the module is activated to initialize the plugin.
	Start() (io.Writer, io.Reader, error)

	// Stop is called after all modules have been completed. It must return
	// promptly, generally by sending an OS kill signal, or risk hanging the
	// client.
	Stop() error

	// GracefulStop will be called before Stop. Stop will not be called until
	// at least the context provided to GracefulStop has expired.
	GracefulStop(context.Context) error
}

// ModuleName returns the module name of a plugin.
func ModuleName(p Module) (string, error) {
	w, r, err := p.Start()
	if err != nil {
		return "", err
	}
	defer func() { _ = p.Stop() }()

	proto := &protocol{in: w, out: bufio.NewScanner(r)}
	return proto.ModuleName()
}

// NewCommandPluginModule constructs a plugin.Module from an OS executable.
//
// For graceful stop behavior, a custom plugin.Module implementation should be used.
func NewCommandPluginModule(pluginCmd *exec.Cmd) Module {
	var cmd *exec.Cmd
	return plugin{
		StartFunc: func() (io.Writer, io.Reader, error) {
			// Duplicate command so that plugin can be started multiple times
			dupcmd := *pluginCmd
			cmd = &dupcmd

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
		StopFunc: func() error {
			if cmd == nil || cmd.Process == nil {
				return nil
			}
			defer func() { cmd = nil }()

			if err := cmd.Process.Kill(); err != nil {
				return err
			}
			return cmd.Wait()
		},
	}
}

type plugin struct {
	// required
	StartFunc func() (io.Writer, io.Reader, error)

	// optional
	StopFunc func() error

	// optional
	GracefulStopFunc func(context.Context) error
}

var _ Module = plugin{}

func (p plugin) Start() (io.Writer, io.Reader, error) { return p.StartFunc() }

func (p plugin) Stop() error {
	if p.StopFunc == nil {
		return nil
	}
	return p.StopFunc()
}

func (p plugin) GracefulStop(ctx context.Context) error {
	if p.GracefulStopFunc == nil {
		return nil
	}
	return p.GracefulStopFunc(ctx)
}
