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
	Modules []string
}

func (d *devmodOwnerModule) HandleInfo(ctx context.Context, messageName string, messageBody io.Reader) error {
	switch messageName {
	case "active":
		var ignore bool
		return cbor.NewDecoder(messageBody).Decode(&ignore)
	case "nummodules":
		var numModules int
		if err := cbor.NewDecoder(messageBody).Decode(&numModules); err != nil {
			return err
		}
		d.Modules = make([]string, numModules)
		return nil
	case "modules":
		return d.parseModules(messageBody)
	}

	dm := reflect.ValueOf(&d.Devmod).Elem()
	for i := range dm.NumField() {
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
	for {
		var chunk serviceinfo.DevmodModulesChunk
		if err := cbor.NewDecoder(messageBody).Decode(&chunk); errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return err
		}
		// If the FDO 2.0 spec is made more clear, validate that start plus len
		// is less than or equal to numModules.
		if chunk.Start < 0 || chunk.Start > len(d.Modules) || chunk.Len < 0 || len(chunk.Modules) != chunk.Len {
			return fmt.Errorf("invalid devmod module chunk")
		}
		if slices.Contains(chunk.Modules, "") {
			return fmt.Errorf("devmod sent an empty module name which is invalid")
		}

		// Handle implementations that don't use the first array item to
		// indicate the start index of the full module array to populate.
		if idx := slices.Index(d.Modules, ""); idx != -1 && chunk.Start != idx {
			chunk.Start = idx
		}

		copy(d.Modules[chunk.Start:chunk.Start+chunk.Len], chunk.Modules)
	}
}

func (d *devmodOwnerModule) ProduceInfo(_ context.Context, _ *serviceinfo.Producer) (bool, bool, error) {
	if d.Modules == nil || slices.Contains(d.Modules, "") {
		return false, false, nil
	}

	// Validate required fields were sent
	if err := d.Validate(); err != nil {
		return false, false, err
	}

	return false, true, nil
}
