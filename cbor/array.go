// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cbor

import (
	"bytes"
)

// ArrayShift returns the first element of a CBOR array type (not text or byte
// strings) as unparsed CBOR and the rest as a CBOR-encoded array of one fewer
// elements. Trailing data will be left intact.
//
// If the CBOR data is invalid or not an array, first will be zero length and
// remaining will be equal to the input data.
//
// This function only operates on array major types and not text strings or
// byte strings.
func ArrayShift(data []byte) (first, remaining []byte) {
	if len(data) == 0 {
		panic("data cannot be empty")
	}

	b := bytes.NewBuffer(data)
	dec := NewDecoder(b)
	length, err := dec.UnwrapArray()
	if err != nil || length == 0 {
		return nil, data
	}

	// Parse the first item from the array contents
	first, err = dec.decodeRaw()
	if err != nil {
		return nil, data
	}

	// Return the first item's CBOR encoding and an array of the remaining data
	// (with length decremented by one)
	return first, append(
		additionalInfo(arrayMajorType, u64Bytes(length-1)),
		b.Bytes()...)
}
