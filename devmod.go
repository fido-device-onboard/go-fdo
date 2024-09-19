// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

type devmodOwnerModule struct {
	serviceinfo.Devmod
	Modules    []string
	numModules int
	done       bool
}

func (d *devmodOwnerModule) HandleInfo(ctx context.Context, messageName string, messageBody io.Reader) error {
	switch messageName {
	case "active":
		var ignore bool
		return cbor.NewDecoder(messageBody).Decode(&ignore)
	case "nummodules":
		return cbor.NewDecoder(messageBody).Decode(&d.numModules)
	case "modules":
		return d.parseModules(messageBody)
	}

	dm := reflect.ValueOf(&d.Devmod).Elem()
	for i := 0; i < dm.NumField(); i++ {
		tag := dm.Type().Field(i).Tag.Get("devmod")
		fieldMessageName, _, _ := strings.Cut(tag, ",")
		if fieldMessageName != messageName {
			continue
		}
		return cbor.NewDecoder(messageBody).Decode(dm.Field(i).Addr().Interface())
	}

	return fmt.Errorf("unknown devmod message name: %s", messageName)
}

func (d *devmodOwnerModule) parseModules(messageBody io.Reader) error {
	if d.Modules == nil {
		d.Modules = make([]string, d.numModules)
	}
	for {
		var chunk serviceinfo.DevmodModulesChunk
		if err := cbor.NewDecoder(messageBody).Decode(&chunk); errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return err
		}
		// If the FDO 1.2 spec is made more clear, validate that start plus len
		// is less than or equal to numModules.
		if chunk.Start < 0 || chunk.Start > d.numModules || chunk.Len < 0 || len(chunk.Modules) != chunk.Len {
			return fmt.Errorf("invalid devmod module chunk")
		}

		// Handle implementations that don't use the first array item to
		// indicate the start index of the full module array to populate.
		if idx := slices.Index(d.Modules, ""); idx != -1 && chunk.Start != idx {
			chunk.Start = idx
		}

		copy(d.Modules[chunk.Start:chunk.Start+chunk.Len], chunk.Modules)
		d.done = chunk.Start+chunk.Len == d.numModules
	}
}

func (d *devmodOwnerModule) ProduceInfo(_ context.Context, _ *serviceinfo.Producer) (bool, bool, error) {
	// Validate required fields were sent before sending IsDone
	if d.done {
		if err := d.Devmod.Validate(); err != nil {
			return false, false, err
		}
		if slices.Contains(d.Modules, "") {
			return false, false, fmt.Errorf("modules list did not match nummodules or included an empty module name")
		}
		return false, true, nil
	}
	return false, false, nil
}
