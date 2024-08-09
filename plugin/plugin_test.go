// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package plugin_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"testing"

	"github.com/fido-device-onboard/go-fdo/fdotest"
	"github.com/fido-device-onboard/go-fdo/plugin"
)

func TestPluginModuleName(t *testing.T) {
	const expectedModuleName = "mockplugin"

	mock := fdotest.NewMockPlugin()
	mock.Routines = func() (func(context.Context, io.Writer) error, func(context.Context, io.Reader) error) {
		gotModuleNameCommand := make(chan struct{})

		return func(ctx context.Context, w io.Writer) error {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-gotModuleNameCommand:
				}

				name := base64.StdEncoding.EncodeToString([]byte(expectedModuleName))
				if _, err := w.Write(append([]byte{'M'}, name...)); err != nil {
					return err
				}
				if _, err := w.Write([]byte{'\n'}); err != nil {
					return err
				}

				return nil
			}, func(ctx context.Context, r io.Reader) error {
				scanner := bufio.NewScanner(r)
				if !scanner.Scan() {
					if err := scanner.Err(); err != nil {
						return err
					}
					return io.ErrUnexpectedEOF
				}

				if scanner.Text() != "M" {
					return fmt.Errorf("expected module name command")
				}

				close(gotModuleNameCommand)
				return nil
			}
	}

	name, err := plugin.ModuleName(mock)
	if err != nil {
		t.Fatal(err)
	}
	if name != expectedModuleName {
		t.Fatalf("expected %q, got %q", expectedModuleName, name)
	}
}
