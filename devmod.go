// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"bufio"
	"fmt"
	"reflect"
	"strings"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

const devmodModuleName = "devmod"

/*
Devmod implements the one required FDO ServiceInfo Module

┌─────────────────┬───────────┬───────────────┬─────────────────────────────────────────────────────────────┐
│devmod:active    │ Required  │ bool          │ Indicates the module is active. Devmod is required on       │
│                 │           │               │ all devices                                                 │
├─────────────────┼───────────┼───────────────┼─────────────────────────────────────────────────────────────┤
│devmod:os        │ Required  │ tstr          │ OS name (e.g., Linux)                                       │
├─────────────────┼───────────┼───────────────┼─────────────────────────────────────────────────────────────┤
│devmod:arch      │ Required  │ tstr          │ Architecture name / instruction set (e.g., X86_64)          │
├─────────────────┼───────────┼───────────────┼─────────────────────────────────────────────────────────────┤
│devmod:version   │ Required  │ tstr          │ Version of OS (e.g., “Ubuntu* 16.0.4LTS”)                   │
├─────────────────┼───────────┼───────────────┼─────────────────────────────────────────────────────────────┤
│devmod:device    │ Required  │ tstr          │ Model specifier for this FIDO Device Onboard Device,        │
│                 │           │               │ manufacturer specific                                       │
├─────────────────┼───────────┼───────────────┼─────────────────────────────────────────────────────────────┤
│devmod:sn        │ Optional  │ tstr/bstr     │ Serial number for this FIDO Device Onboard Device,          │
│                 │           │               │ manufacturer specific                                       │
├─────────────────┼───────────┼───────────────┼─────────────────────────────────────────────────────────────┤
│devmod:pathsep   │ Optional  │ tstr          │ Filename path separator, between the directory and          │
│                 │           │               │ sub-directory (e.g., ‘/’ or ‘\’)                            │
├─────────────────┼───────────┼───────────────┼─────────────────────────────────────────────────────────────┤
│devmod:sep       │ Required  │ tstr          │ Filename separator, that works to make lists of file        │
│                 │           │               │ names (e.g., ‘:’ or ‘;’)                                    │
├─────────────────┼───────────┼───────────────┼─────────────────────────────────────────────────────────────┤
│devmod:nl        │ Optional  │ tstr          │ Newline sequence (e.g., a tstr of length 1 containing       │
│                 │           │               │ U+000A; a tstr of length 2 containing U+000D followed       │
│                 │           │               │ by U+000A)                                                  │
├─────────────────┼───────────┼───────────────┼─────────────────────────────────────────────────────────────┤
│devmod:tmp       │ Optional  │ tstr          │ Location of temporary directory, including terminating      │
│                 │           │               │ file separator (e.g., “/tmp”)                               │
├─────────────────┼───────────┼───────────────┼─────────────────────────────────────────────────────────────┤
│devmod:dir       │ Optional  │ tstr          │ Location of suggested installation directory, including     │
│                 │           │               │ terminating file separator (e.g., “.” or “/home/fdo” or     │
│                 │           │               │ “c:\Program Files\fdo”)                                     │
├─────────────────┼───────────┼───────────────┼─────────────────────────────────────────────────────────────┤
│devmod:progenv   │ Optional  │ tstr          │ Programming environment. See Table ‎3‑22 (e.g.,        │
│                 │           │               │ “bin:java:py3:py2”)                                         │
├─────────────────┼───────────┼───────────────┼─────────────────────────────────────────────────────────────┤
│devmod:bin       │ Required  │ tstr          │ Either the same value as “arch”, or a list of machine       │
│                 │           │               │ formats that can be interpreted by this device, in          │
│                 │           │               │ preference order, separated by the “sep” value (e.g.,       │
│                 │           │               │ “x86:X86_64”)                                               │
├─────────────────┼───────────┼───────────────┼─────────────────────────────────────────────────────────────┤
│devmod:mudurl    │ Optional  │ tstr          │ URL for the Manufacturer Usage Description file that        │
│                 │           │               │ relates to this device                                      │
├─────────────────┼───────────┼───────────────┼─────────────────────────────────────────────────────────────┤
│devmod:nummodules│ Required  │ uint          │ Number of modules supported by this FIDO Device Onboard     │
│                 │           │               │ Device                                                      │
├─────────────────┼───────────┼───────────────┼─────────────────────────────────────────────────────────────┤
│devmod:modules   │ Required  │ [uint, uint,  │ Enumerates the modules supported by this FIDO Device        │
│                 │           │ tstr1, tstr2, │ Onboard Device. The first element is an integer from        │
│                 │           │ ...]          │ zero to devmod:nummodules. The second element is the        │
│                 │           │               │ number of module names to return The subsequent elements    │
│                 │           │               │ are module names. During the initial Device ServiceInfo,    │
│                 │           │               │ the device sends the complete list of modules to the Owner. │
│                 │           │               │ If the list is long, it might require more than one         │
│                 │           │               │ ServiceInfo message.                                        │
└─────────────────┴───────────┴───────────────┴─────────────────────────────────────────────────────────────┘
*/
type Devmod struct {
	Os      string `devmod:"os,required"`
	Arch    string `devmod:"arch,required"`
	Version string `devmod:"version,required"`
	Device  string `devmod:"device,required"`
	Serial  []byte `devmod:"sn"`
	PathSep string `devmod:"pathsep"`
	FileSep string `devmod:"sep,required"`
	Newline string `devmod:"nl"`
	Temp    string `devmod:"tmp"`
	Dir     string `devmod:"dir"`
	ProgEnv string `devmod:"progenv"`
	Bin     string `devmod:"bin,required"`
	MudURL  string `devmod:"mudurl"`
}

// Write the devmod messages.
func (d *Devmod) Write(modules []string, mtu uint16, w *serviceinfo.UnchunkWriter) {
	defer func() { _ = w.Close() }()
	buf := bufio.NewWriterSize(w, int(mtu))
	enc := cbor.NewEncoder(buf)

	// Active must always be true
	if err := w.NextServiceInfo(devmodModuleName, "active"); err != nil {
		_ = w.CloseWithError(err)
		return
	}
	if err := enc.Encode(true); err != nil {
		_ = w.CloseWithError(err)
		return
	}

	// Use reflection to get each field and check required fields are not empty
	dm := reflect.ValueOf(d).Elem()
	for i := 0; i < dm.NumField(); i++ {
		tag := dm.Type().Field(i).Tag.Get("devmod")
		messageName, opt, _ := strings.Cut(tag, ",")
		if opt == "required" && dm.Field(i).IsZero() {
			_ = w.CloseWithError(fmt.Errorf("missing required devmod field: %s", messageName))
			return
		}
		if dm.Field(i).Len() == 0 {
			continue
		}
		if err := w.NextServiceInfo(devmodModuleName, messageName); err != nil {
			_ = w.CloseWithError(err)
			return
		}
		if err := enc.Encode(dm.Field(i).Interface()); err != nil {
			_ = w.CloseWithError(err)
			return
		}
		if err := buf.Flush(); err != nil {
			_ = w.CloseWithError(err)
			return
		}
	}

	if err := d.writeModuleMessages(modules, mtu, w); err != nil {
		_ = w.CloseWithError(err)
		return
	}
}

type devmodModulesChunk struct {
	Start   int
	Len     int
	Modules []string
}

func (d *Devmod) writeModuleMessages(modules []string, mtu uint16, w *serviceinfo.UnchunkWriter) error {
	buf := bufio.NewWriterSize(w, int(mtu))
	enc := cbor.NewEncoder(buf)

	writeChunk := func(chunk devmodModulesChunk) error {
		if err := w.NextServiceInfo(devmodModuleName, "modules"); err != nil {
			return err
		}
		if err := enc.Encode(chunk); err != nil {
			return err
		}
		return buf.Flush()
	}

	if err := w.NextServiceInfo(devmodModuleName, "nummodules"); err != nil {
		return err
	}
	if err := enc.Encode(len(modules)); err != nil {
		return err
	}
	if err := buf.Flush(); err != nil {
		return err
	}

	// Start a new message so that full MTU is available
	if err := w.ForceNewMessage(); err != nil {
		return err
	}

	// Build chunks iteratively until MTU is exceeded, back out the last
	// module, write chunk, and continue until the last chunk is encoded.
	const key = devmodModuleName + ":" + "modules"
	var chunk devmodModulesChunk
	for len(modules) > 0 {
		// Add module to chunk
		chunk.Len++
		chunk.Modules = append(chunk.Modules, modules[0])

		// Brute force computing the encoded size by actually encoding it
		var size sizewriter
		if err := cbor.NewEncoder(&size).Encode([][]any{{key, chunk}}); err != nil {
			return fmt.Errorf("error calculating size of devmod:modules ServiceInfo: %w", err)
		}

		// Continue if MTU is not exceeded
		if uint16(size) <= mtu {
			modules = modules[1:]
			continue
		}

		// Back out last module and encode chunk
		if len(chunk.Modules) == 1 {
			return fmt.Errorf("MTU too small to send devmod module name alone")
		}
		chunk.Len--
		chunk.Modules = chunk.Modules[:len(chunk.Modules)-1]
		if err := writeChunk(chunk); err != nil {
			return err
		}

		// Reset chunk
		chunk = devmodModulesChunk{Start: chunk.Start + chunk.Len}
	}

	return writeChunk(chunk)
}

type sizewriter int

func (w *sizewriter) Write(p []byte) (int, error) { *w += sizewriter(len(p)); return len(p), nil }
