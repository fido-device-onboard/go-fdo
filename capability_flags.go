// SPDX-FileCopyrightText: (C) 2024 Intel Corperation & Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"io"
	"github.com/fido-device-onboard/go-fdo/cbor"
)

type CapabilityFlags struct {
	Flags []byte 
	VendorUnique []string `cbor:",omitempty"`
}

// Return number of fields that we are NOT marshalling because
// they are EMPTY (upstream code will use to resize arrays
// correctly. Since we will not return a venorUnique array
// at all if there are zero entries in it, return 1 in this case

func (f CapabilityFlags) FlatMarshalEmptyCount() int {
	
	if len(f.VendorUnique) == 0 {
		return 1
	}
	return 0
}

func (f CapabilityFlags) FlatMarshalCBOR(w io.Writer) error {
	e:=cbor.NewEncoder(w)
	if err := e.Encode(f.Flags); err != nil {
		return err
	}
	if len(f.VendorUnique) > 0 {
		e.Encode(f.VendorUnique)
	}
	return nil
}

func (f *CapabilityFlags) FlatUnmarshalCBOR(r io.Reader) error {
	if err := cbor.NewDecoder(r).Decode(&f.Flags); err != nil {
		return err
	}
	cbor.NewDecoder(r).Decode(&f.VendorUnique)
	return nil
}

const (
    DelegateSupportFlag = 1
)

var VendorUniqueFlags = []string{"com.example.test"}

// These are based on implmenetation, and therefore 
// should be contants
var GlobalCapabilityFlags = CapabilityFlags{
	Flags: []byte{DelegateSupportFlag}, // Delegate support
	VendorUnique: VendorUniqueFlags,
}

