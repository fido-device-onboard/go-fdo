// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo_test

import (
	"errors"
	"io"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

func TestDevmodRequired(t *testing.T) {
	mtu := uint16(1300)
	for i, devmod := range []fdo.Devmod{
		{},
		{Os: runtime.GOOS},
		{
			Arch:    runtime.GOARCH,
			Version: "TestOS",
			Device:  "UnitMcUnitFace",
			FileSep: ";",
			Bin:     runtime.GOARCH,
		},
	} {
		t.Run("Devmod "+strconv.Itoa(i), func(t *testing.T) {
			r, w := serviceinfo.NewChunkOutPipe(0)
			defer func() { _ = w.Close() }()

			go devmod.Write([]string{"devmod"}, mtu, w)

			for {
				_, err := r.ReadChunk(mtu)
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					if !strings.Contains(err.Error(), "missing required devmod field") {
						t.Fatalf("expected error for missing required field, got: %v", err)
					}
					return
				}
			}

			t.Fatal("expected to receive an error for a missing required devmod field")
		})
	}
}

func TestDevmod(t *testing.T) {
	devmod := fdo.Devmod{
		Os:      runtime.GOOS,
		Arch:    runtime.GOARCH,
		Version: "TestOS",
		Device:  "UnitMcUnitFace",
		FileSep: ";",
		Bin:     runtime.GOARCH,
	}
	modules := []string{"devmod", "unit-test1", "unit-test2", "unit-test3"}

	r, w := serviceinfo.NewChunkOutPipe(0)
	defer func() { _ = w.Close() }()

	mtu := uint16(40)
	go devmod.Write(modules, mtu, w)
	var chunks []*serviceinfo.KV
	for {
		chunk, err := r.ReadChunk(mtu)
		if errors.Is(err, io.EOF) {
			break
		}
		if errors.Is(err, serviceinfo.ErrSizeTooSmall) {
			// Indicates to ServiceInfo auto-chunker to start a new ServiceInfo
			// for grouping KVs
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		chunks = append(chunks, chunk)

		// Chunk 1: [Key="devmod:active",Val=f5]
		// Chunk 2: [Key="devmod:os",Val=65 6c 69 6e 75 78]
		// Chunk 3: [Key="devmod:arch",Val=65 61 6d 64 36 34]
		// Chunk 4: [Key="devmod:version",Val=66 54 65 73 74 4f 53]
		// Chunk 5: [Key="devmod:device",Val=6e 55 6e 69 74 4d 63 55 6e 69 74 46 61 63 65]
		// Chunk 6: [Key="devmod:sep",Val=61 3b]
		// Chunk 7: [Key="devmod:bin",Val=65 61 6d 64 36 34]
		// Chunk 8: [Key="devmod:nummodules",Val=04]
		// Chunk 9: [Key="devmod:modules",Val=83 00 02 82 66 64 65 76 6d 6f 64 6a 75 6e 69 74 2d 74 65 73 74 31]
		// Chunk 10: [Key="devmod:modules",Val=83 02 01 81 6a 75 6e 69 74 2d 74 65 73 74 32]
		// Chunk 11: [Key="devmod:modules",Val=83 03 01 81 6a 75 6e 69 74 2d 74 65 73 74 33]
		t.Logf("Chunk %d: %+v\n", len(chunks), chunk)
	}

	// 8 chunks + # of module chunks
	if modChunks := len(chunks) - 8; modChunks != 3 {
		t.Errorf("expected devmod:modules to be written in 3 chunks, got %d", modChunks)
	}
}
