// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package plugin_test

import (
	"testing"

	"github.com/fido-device-onboard/go-fdo/fdotest"
	"github.com/fido-device-onboard/go-fdo/plugin"
)

func TestPluginModuleName(t *testing.T) {
	const expectedModuleName = "mockplugin"

	mock := new(fdotest.MockPlugin)
	mock.Routines = fdotest.ModuleNameOnlyRoutines(expectedModuleName)

	name, err := plugin.ModuleName(mock)
	if err != nil {
		t.Fatal(err)
	}
	if name != expectedModuleName {
		t.Fatalf("expected %q, got %q", expectedModuleName, name)
	}
}
