// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

const devmodModuleName = "devmod"

/*
devMod implements the one required FDO ServiceInfo Module

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
func devMod(modules []string, w *serviceinfo.UnchunkWriter) {
	check := func(err error) { _ = w.CloseWithError(err) }
	enc := cbor.NewEncoder(w)

	check(w.NextServiceInfo(devmodModuleName, "active"))
	check(enc.Encode(true))

	check(w.NextServiceInfo(devmodModuleName, "os"))
	check(enc.Encode("")) // TODO: GOOS

	check(w.NextServiceInfo(devmodModuleName, "arch"))
	check(enc.Encode("")) // TODO: GOARCH

	check(w.NextServiceInfo(devmodModuleName, "version"))
	check(enc.Encode("")) // TODO: os-release?

	check(w.NextServiceInfo(devmodModuleName, "device"))
	check(enc.Encode("")) // TODO: ?

	check(w.NextServiceInfo(devmodModuleName, "bin"))
	check(enc.Encode("")) // TODO: ?

	check(w.NextServiceInfo(devmodModuleName, "nummodules"))
	check(enc.Encode(len(modules)))

	check(w.NextServiceInfo(devmodModuleName, "modules"))
	check(enc.Encode(modules)) // FIXME: How to do custom chunking? Must know MTU.
}
