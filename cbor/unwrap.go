// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cbor

import (
	"fmt"
	"slices"
)

// ErrNullOrUndefined is wrapped and returned in Unwrap/Untag functions to
// allow handling of null or undefined values.
var ErrNullOrUndefined = fmt.Errorf("null or undefined")

// UnwrapArray ensures the next type to decode is an array and returns its
// length, progressing the underlying reader to the start of the first item.
//
// If the next value is the undefined or null simple value, err will wrap
// ErrNullOrUndefined.
func (d *Decoder) UnwrapArray() (uint64, error) { return d.unwrap(arrayMajorType) }

// UnwrapBytes ensures the next type to decode is either a text or byte string
// and returns its length, progressing the underlying reader to the start of
// the data.
//
// If the next value is the undefined or null simple value, err will wrap
// ErrNullOrUndefined.
func (d *Decoder) UnwrapBytes() (uint64, error) {
	return d.unwrap(byteStringMajorType, textStringMajorType)
}

// Untag ensures the next type to decode is a tag and returns the tag number,
// progressing the underlying reader to the start of the tag value.
//
// If the next value is the undefined or null simple value, err will wrap
// ErrNullOrUndefined.
func (d *Decoder) Untag() (uint64, error) { return d.unwrap(tagMajorType) }

func (d *Decoder) unwrap(allowedTypes ...byte) (uint64, error) {
	highThreeBits, lowFiveBits, additional, err := d.typeInfo()
	if err != nil {
		return 0, err
	}
	if highThreeBits == simpleMajorType && (lowFiveBits == undefinedVal || lowFiveBits == nullVal) {
		return 0, fmt.Errorf("unexpected type: %x: %w", highThreeBits, ErrNullOrUndefined)
	}
	if !slices.Contains(allowedTypes, highThreeBits) {
		return 0, fmt.Errorf("unexpected type: %x", highThreeBits)
	}
	if len(additional) == 0 {
		additional = []byte{lowFiveBits}
	}
	return toU64(additional), nil
}
