// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

/*
Package cbor implements a basic encoding/decoding API for RFC 8949 Concise
Binary Object Representation (CBOR).

Not supported:

  - Indefinite length arrays, maps, byte strings, or text strings
  - Simple values other than bool, null, and undefined
  - Numbers greater than 64 bits
  - Decoding structs with more than one omittable field
  - Encoding/decoding structs to/from CBOR maps
  - Decoding CBOR maps with array/map/uncomparable keys to Go maps
  - Floats (yet)
  - UTF-8 validation of strings

However, the Marshaler/Unmarshaler interfaces allow any determinate sized
CBOR item to be encoded to/from any Go type.

Specifically, >1 omittable struct fields (i.e. `omitempty`) is not supported,
because handling this case is not generally solvable and depends on the
specification of the API being implemented.

# Encoding

Encoding can be done with [any] or [Marshal]. Using an [Encoder] may be more
efficient when writing many items if a buffered writer is used. It also allows
for setting encoding options.

	var w bytes.Buffer
	enc := cbor.NewEncoder(&w)

	# Simple
	_ = enc.Encode(true)        // true
	_ = enc.Encode(false)       // false
	_ = enc.Encode((*int)(nil)) // null

	# Numbers
	_ = enc.Encode(-1) // 0x20

	// All encode to 0x01
	_ = enc.Encode(int(1))
	_ = enc.Encode(int8(1))
	_ = enc.Encode(int16(1))
	_ = enc.Encode(int32(1))
	_ = enc.Encode(int64(1))
	_ = enc.Encode(uint(1))
	_ = enc.Encode(uint8(1))
	_ = enc.Encode(uint16(1))
	_ = enc.Encode(uint32(1))
	_ = enc.Encode(uint64(1))

	# Binary/Text
	_ = enc.Encode([]byte{0x01, 0x02}) // 0x42 0x01 0x02
	_ = enc.Encode("Hello World!")

	# Homogeneous Arrays
	_ = enc.Encode([]int{1, 2, 3})
	_ = enc.Encode([][]byte{{0x01}, {0x02}, {0x03}})

	# Heterogeneous Arrays (Tuples/Structs)
	_ = enc.Encode(struct{ A int }{A: 1}) // 0x81, 0x01
	_ = enc.Encode(struct{ A int; B string }{A: 1, B: "IETF"}) // 0x82, 0x01, 0x64, 0x49, 0x45, 0x54, 0x46

	// Struct tags: change order by setting weights
	_ = enc.Encode(struct{
		A int    `cbor:"1"`
		B string `cbor:"0"
	}{
		A: 1,
		B: "IETF",
	}) // 0x82, 0x64, 0x49, 0x45, 0x54, 0x46, 0x01

	// Struct tags: ignore fields
	_ = enc.Encode(struct{
		A int
		B string
		C bool `cbor:"-"`
	}{
		A: 1,
		B: "IETF",
		C: true,
	}) // 0x82, 0x01, 0x64, 0x49, 0x45, 0x54, 0x46

	// Struct embedded fields
	type Embed struct{ A int }
	_ = enc.Encode(struct{
		Embed
		B string
	}{
		Embed: Embed{A: 1},
		B:     "IETF",
	}) // 0x82, 0x01, 0x64, 0x49, 0x45, 0x54, 0x46

	# Maps
	_ = enc.Encode(map[int]string{1: "hello"})
	// Empty struct values also work (for sets)
	_ = enc.Encode(map[int]struct{}{1: {}, 2: {}})
	// Core deterministic encoding is used by default
	_ = enc.Encode(map[int]struct{}{1: {}, 2: {}}, "hello": {}) // always ordered 1, 2, "hello"

	# Tags
	_ = enc.Encode(cbor.Tag[string]{Num: 42, Val: "Meaning of life"})
	_ = enc.Encode(cbor.Tag[[]string]{Num: 42, Val: []string{"Meaning", "of", "life"}})

# Decoding

Decoding can be done with [Decoder.Decode] or [Unmarshal]. Using a [Decoder] is
generally more memory efficient than reading an entire [io.Reader] into a
[]byte and then unmarshaling it.

	# Simple
	var b bool
	_ = cbor.Unmarshal([]byte{0xf4}, &b) // b = false
	_ = cbor.Unmarshal([]byte{0xf5}, &b) // b = true
	var i int
	ip := &i
	_ = cbor.Unmarshal([]byte{0xf6}, &ip) // ip = nil

	# Numbers
	var i8 int8
	_ = cbor.Unmarshal([]byte{0x01}, &i8) // i8 = 1
	_ = cbor.Unmarshal([]0byte{x20}, &i8) // i8 = -1

	# Binary/Text
	var bin []byte
	_ = cbor.Unmarshal([]byte{0x45, 0x68, 0x65, 0x6c, 0x6c, 0x6f}, &bin) // bin = ['h', 'e', 'l', 'l', 'o']
	var text string
	_ = cbor.Unmarshal([]byte{0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f}, &text) // text = "hello"

	# Homogeneous Arrays
	var ints []int
	_ = cbor.Unmarshal([]byte{0x85, 0x01, 0x02, 0x03, 0x04, 0x05}, &ints) // ints = [1, 2, 3, 4, 5]

	# Heterogeneous Arrays (Tuples/Structs)
	var s1 struct{ A int }
	_ = cbor.Unmarshal([]byte{0x81, 0x01}, &s1) // s1 = {A: 1}
	var s2 struct{ A int; B string }
	_ = cbor.Unmarshal([]byte{0x82, 0x01, 0x64, 0x49, 0x45, 0x54, 0x46}, &s2) // s2 = {A: 1, B: "IETF"}

	// Struct tags: change order by setting weights
	var s3 struct{
		A int    `cbor:"1"`
		B string `cbor:"0"
	}
	_ = cbor.Unmarshal([]byte{0x82, 0x64, 0x49, 0x45, 0x54, 0x46, 0x01}, &s3) // s3 = {A: 1, B: "IETF"}

	// Struct tags: ignore fields
	var s4 struct{
		A int
		B string
		C bool `cbor:"-"`
	}
	_ = cbor.Unmarshal([]byte{0x82, 0x01, 0x64, 0x49, 0x45, 0x54, 0x46}, &s4) // s4 = {A: 1, B: "IETF", C: false}

	// Struct tags: omit empty
	var s5 struct{
		A int
		B string
		C bool `cbor:",omitempty"`
	}
	_ = cbor.Unmarshal([]byte{0x82, 0x01, 0x64, 0x49, 0x45, 0x54, 0x46}, &s5) // s5 = {A: 1, B: "IETF", C: false}

	// Struct embedded fields
	type Embed struct{ A int }
	var s6 struct{
		Embed
		B string
	}
	_ = cbor.Unmarshal([]byte{0x82, 0x01, 0x64, 0x49, 0x45, 0x54, 0x46}, &s6) // s6 = {Embed: {A: 1}, B: "IETF"}

	# Maps
	var m1 map[int]int // m = nil
	_ = cbor.Unmarshal([]byte{0xa0}, &m1) // m1 = {} <- non-nil!
	_ = cbor.Unmarshal([]byte{0xa2, 0x01, 0x02, 0x03, 0x04}, &m1) // m1 = {1: 2, 3: 4}

	# Tags
	var tag cbor.Tag[string]
	_ = cbor.Unmarshal([]byte{0xc1, 0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f}, &tag)
	// tag = {Num: 1, Val: "hello"}

When decoding into an any/empty interface type, the following CBOR to Go type
mapping is used:

	Unsigned     -> int64
	Negative     -> int64
	Byte String  -> []byte
	Text String  -> string
	Array        -> []interface{}
	Map          -> map[interface{}]interface{}
	Tag          -> cbor.Tag[cbor.RawBytes]
	Simple(Bool) -> bool

Decoding other types will fail, because it is not clear what memory to
allocate. Even null cannot be decoded, because nil values still require a type
in Go.
*/
package cbor
