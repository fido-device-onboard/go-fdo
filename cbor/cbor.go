/*
cbor implements a basic encoding/decoding API for RFC 8949 Concise Binary
Object Representation (CBOR).

Not supported:

  - Indefinite length arrays, maps, byte strings, or text strings
  - Simple values other than bool, null, and undefined
  - Numbers greater than 64 bits
  - Encoding/decoding structs to/from CBOR maps
  - Floats (yet)

However, the Marshaler/Unmarshaler interfaces allow any determinate sized
CBOR item to be encoded to/from any Go type.

# Encoding

Encoding can be done with [Encoder.Encode] or [Marshal]. Using an [Encoder] may
be more efficient when writing many items if a buffered writer is used. It also
allows for setting encoding options.

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

	# Maps
	_ = enc.Encode(map[int]string{1: "hello"})
	// Empty struct values also work (for sets)
	_ = enc.Encode(map[int]struct{}{1: {}, 2: {}})

	# Tags
	_ = enc.Encode(cbor.Tag{Number: 42, EncodeVal: "Meaning of life"})
	_ = enc.Encode(cbor.Tag{Number: 42, EncodeVal: []string{"Meaning", "of", "life"}})

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
	_ = cbor.Unmarshal([]byte{0x82, 0x01, 0x64, 0x49, 0x45, 0x54, 0x46}, &s4) // s4 = {A: 1, B: "IETF"}

	# Maps
	var m1 map[int]int // m = nil
	_ = cbor.Unmarshal([]byte{0xa0}, &m1) // m1 = {} <- non-nil!
	_ = cbor.Unmarshal([]byte{0xa2, 0x01, 0x02, 0x03, 0x04}, &m1) // m1 = {1: 2, 3: 4}

	# Tags
	var tag cbor.Tag
	_ = cbor.Unmarshal([]byte{0xc1, 0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f}, &tag)
	// tag = {Number: 1, DecodedVal: [0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f]}
	var tagged string
	_ = cbor.Unmarshal([]byte(cbor.DecodedVal), &tagged) // tagged = "hello"

When decoding into an any/empty interface type, the following CBOR to Go type
mapping is used:

	Unsigned     -> int64
	Negative     -> int64
	Byte String  -> []byte
	Text String  -> string
	Array        -> []interface{}
	Map          -> map[interface{}]interface{}
	Tag          -> cbor.Tag
	Simple(Bool) -> bool

Decoding other types will fail, because it is not clear what memory to
allocate. Even null cannot be decoded, because nil values still require a type
in Go.
*/
package cbor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// Major types (high 3 bits)
const (
	unsignedIntMajorType byte = 0x00
	negativeIntMajorType byte = 0x01
	byteStringMajorType  byte = 0x02
	textStringMajorType  byte = 0x03
	arrayMajorType       byte = 0x04
	mapMajorType         byte = 0x05
	tagMajorType         byte = 0x06
	simpleMajorType      byte = 0x07
)

// Additional info (low 5 bits)
const (
	oneByteAdditional    byte = 0x18
	twoBytesAdditional   byte = 0x19
	fourBytesAdditional  byte = 0x1a
	eightBytesAdditional byte = 0x1b
)

// Well-known simple values
const (
	falseVal     byte = 0x14
	trueVal      byte = 0x15
	nullVal      byte = 0x16
	undefinedVal byte = 0x17
	halfFloat    byte = 0x18
	singleFloat  byte = 0x19
	doubleFloat  byte = 0x1a
)

// Bitmasks
const (
	threeBitMask byte = 0x07
	fiveBitMask  byte = 0x1f
)

// ErrUnsupportedType means that a value of this type cannot be encoded.
type ErrUnsupportedType struct {
	typeName string
}

func (e ErrUnsupportedType) Error() string {
	return fmt.Sprintf("unsupported type: %s", e.typeName)
}

// Marshaler is the interface implemented by types that can marshal themselves
// into valid CBOR.
type Marshaler interface {
	MarshalCBOR() ([]byte, error)
}

// Unmarshaler is the interface implemented by types that can unmarshal a CBOR
// description of themselves. The data is invalid upon the function returning.
type Unmarshaler interface {
	UnmarshalCBOR([]byte) error
}

// RawBytes encodes and decodes untransformed. When encoding, it must contain
// valid CBOR.
type RawBytes []byte

func (b RawBytes) MarshalCBOR() ([]byte, error) { return b, nil }

func (b *RawBytes) UnmarshalCBOR(p []byte) error { *b = p; return nil }

// Tag is a tagged CBOR type. When decoding, it is expected that the tag number
// will affect how the underlying data is parsed. A single CBOR item is decoded
// as raw bytes to be further parsed with [Unmarshal].
type Tag struct {
	// Any integer 0..(2**64)-1
	Number uint64

	// Value to encode when passed to Encode/Marshal
	EncodeVal any

	// Raw data set in Decode/Unmarshal
	//
	// NOTE: Be sure to type convert into []byte before calling Unmarshal!
	DecodedVal RawBytes
}

// Marshal any type into CBOR.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := NewEncoder(&buf).Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Unmarshal any CBOR data. v must be a pointer type.
func Unmarshal(data []byte, v any) error {
	buf := bytes.NewBuffer(data)
	if err := NewDecoder(buf).Decode(v); err != nil {
		return err
	}
	if buf.Len() > 0 {
		return fmt.Errorf("unmarshal did not consume all data, had extra %d bytes: % x", buf.Len(), buf.Bytes())
	}
	return nil
}

// Decoder iteratively consumes a reader, decoding CBOR types.
type Decoder struct {
	r io.Reader
}

// NewDecoder returns a new Decoder. The [io.Reader] is not copied.
func NewDecoder(r io.Reader) *Decoder { return &Decoder{r: r} }

// Decode a single CBOR item from the internal [io.Reader].
func (d *Decoder) Decode(v any) error {
	// Use UnmarshalCBOR when value is an interface implementing Unmarshaler
	if u, ok := v.(Unmarshaler); ok {
		b, err := d.decodeRaw()
		if err != nil {
			return err
		}
		return u.UnmarshalCBOR(b)
	}

	// Ensure that v is a pointer type
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return fmt.Errorf("type for decoding must be a non-nil pointer value, got %T", v)
	}
	deref := rv.Elem()

	// If v points to a nil slice or map, allocate an empty one
	switch deref.Kind() {
	case reflect.Slice:
		newSlice := reflect.MakeSlice(deref.Type(), 0, 0)
		deref.Set(newSlice)
	case reflect.Map:
		newMap := reflect.MakeMap(deref.Type())
		deref.Set(newMap)
	}

	return d.decodeVal(deref)
}

// Decode one item to bytes
func (d *Decoder) decodeRaw() ([]byte, error) {
	highThreeBits, lowFiveBits, additional, err := d.typeInfo()
	if err != nil {
		return nil, err
	}

	head := append([]byte{(highThreeBits << 5) | lowFiveBits}, additional...)

	switch highThreeBits {
	// Types containing only first byte and additional data
	case unsignedIntMajorType, negativeIntMajorType, simpleMajorType:
		return head, nil

	// Types containing a well-known size without decoding nested types
	case byteStringMajorType, textStringMajorType:
		length := toU64(additional)
		if lowFiveBits < 0x18 {
			length = uint64(lowFiveBits)
		}
		b := make([]byte, length)
		if _, err := d.r.Read(b); err != nil {
			return nil, err
		}
		return append(head, b...), nil

	// Types which must be fully decoded to know their size
	case arrayMajorType, mapMajorType:
		length := toU64(additional)
		if lowFiveBits < 0x18 {
			length = uint64(lowFiveBits)
		}
		if highThreeBits == mapMajorType {
			length *= 2
		}

		decoded := head
		for i := 0; i < int(length); i++ {
			b, err := d.decodeRaw()
			if err != nil {
				return nil, fmt.Errorf("error decoding array/map at item %d: %w", i, err)
			}
			decoded = append(decoded, b...)
		}
		return decoded, nil

	// Tag types are decoded like a simple value followed by another value
	case tagMajorType:
		wrapped, err := d.decodeRaw()
		if err != nil {
			return nil, err
		}
		return append(head, wrapped...), nil
	}

	panic("unreachable")
}

// Decode one item into a settable value
func (d *Decoder) decodeVal(rv reflect.Value) error {
	// Read initial bytes
	highThreeBits, lowFiveBits, additional, err := d.typeInfo()
	if err != nil {
		return err
	}

	// If the low five bits are 0..23 then use them in additional so that a
	// single additional byte can contain any value 0-255
	if lowFiveBits < 0x18 {
		additional = []byte{lowFiveBits}
	}

	// Allow rv to be a pointer for nullable types
	//
	// i.e. Pass a **int to Unmarshal in order to read either an int or null
	if rv.Kind() == reflect.Pointer {
		// If the value to decode is null, set the pointer to nil
		if (highThreeBits == simpleMajorType) && (lowFiveBits == nullVal || lowFiveBits == undefinedVal) {
			// The zero value of a pointer is nil
			rv.SetZero()
			return nil
		}

		// The value to decode is not null, so allocate if the pointer is nil
		if rv.IsNil() {
			rv.Set(reflect.New(rv.Type().Elem()))
		}

		// Dereference the pointer
		rv = rv.Elem()
	}

	// Dispatch decoding by major type
	switch highThreeBits {
	case unsignedIntMajorType:
		allocateNilAny(rv, int64(0))
		return d.decodePositive(rv, additional)
	case negativeIntMajorType:
		allocateNilAny(rv, int64(0))
		return d.decodeNegative(rv, additional)
	case byteStringMajorType:
		allocateNilAny(rv, []byte(nil))
		return d.decodeByteSlice(rv, additional)
	case textStringMajorType:
		allocateNilAny(rv, "")
		return d.decodeByteSlice(rv, additional)
	case arrayMajorType:
		allocateNilAny(rv, []any(nil))
		return d.decodeArray(rv, additional)
	case mapMajorType:
		allocateNilAny(rv, map[any]any(nil))
		return d.decodeMap(rv, additional)
	case tagMajorType:
		allocateNilAny(rv, Tag{})
		return d.decodeTag(rv, additional)
	case simpleMajorType:
		if lowFiveBits == falseVal || lowFiveBits == trueVal {
			allocateNilAny(rv, false)
		}
		return d.decodeSimple(rv, lowFiveBits, additional)
	}

	panic("unreachable")
}

// Initialize the memory of a value if it is a nil interface{}/any type.
func allocateNilAny(maybeUnsetVal reflect.Value, defaultVal any) {
	if maybeUnsetVal.Kind() != reflect.Interface || maybeUnsetVal.NumMethod() > 0 {
		// Not an empty interface
		return
	}
	if !maybeUnsetVal.IsNil() {
		// Already has an underlying value
		return
	}

	// Create a new zero value of the defaultVal type
	newType := reflect.TypeOf(defaultVal)
	switch newType.Kind() {
	case reflect.Map:
		// Explicitly allocate for maps because the zero value is nil.
		maybeUnsetVal.Set(reflect.MakeMap(newType))
	case reflect.Slice:
		// This slice will need to be created again with its correct length,
		// but for now we still allocate it in order to pass type information.
		maybeUnsetVal.Set(reflect.MakeSlice(newType, 0, 0))
	default:
		maybeUnsetVal.Set(reflect.New(newType).Elem())
	}
}

func (d *Decoder) decodePositive(rv reflect.Value, additional []byte) error {
	u64 := toU64(additional)

	// Check that value fits
	overflows := false
	kind := rv.Kind()
	if kind == reflect.Interface && !rv.IsNil() {
		kind = rv.Elem().Kind()
	}
	switch kind {
	case reflect.Uint:
		overflows = len(additional) > (bits.UintSize / 8)
	case reflect.Uint8:
		overflows = len(additional) > 1
	case reflect.Uint16:
		overflows = len(additional) > 2
	case reflect.Uint32:
		overflows = len(additional) > 4
	case reflect.Uint64:
		overflows = len(additional) > 8 // always fits
	case reflect.Int:
		overflows = len(additional) > (bits.UintSize/8) || int(u64) < 0
	case reflect.Int8:
		overflows = len(additional) > 1 || int8(u64) < 0
	case reflect.Int16:
		overflows = len(additional) > 2 || int16(u64) < 0
	case reflect.Int32:
		overflows = len(additional) > 4 || int32(u64) < 0
	case reflect.Int64:
		overflows = len(additional) > 8 || int64(u64) < 0
	default:
		return fmt.Errorf("%w: only primitive (u)int(N) types supported",
			ErrUnsupportedType{typeName: rv.Type().Name()})
	}
	if overflows {
		return fmt.Errorf("%w: value overflows",
			ErrUnsupportedType{typeName: rv.Type().Name()})
	}

	// Note that setting cannot be done with reflect.Value.SetXXX because the
	// reflect.Value may be an interface and its Elem() is not settable.
	switch kind {
	case reflect.Uint:
		rv.Set(reflect.ValueOf(uint(u64)))
	case reflect.Uint8:
		rv.Set(reflect.ValueOf(uint8(u64)))
	case reflect.Uint16:
		rv.Set(reflect.ValueOf(uint16(u64)))
	case reflect.Uint32:
		rv.Set(reflect.ValueOf(uint32(u64)))
	case reflect.Uint64:
		rv.Set(reflect.ValueOf(uint64(u64)))
	case reflect.Int:
		rv.Set(reflect.ValueOf(int(u64)))
	case reflect.Int8:
		rv.Set(reflect.ValueOf(int8(u64)))
	case reflect.Int16:
		rv.Set(reflect.ValueOf(int16(u64)))
	case reflect.Int32:
		rv.Set(reflect.ValueOf(int32(u64)))
	case reflect.Int64:
		rv.Set(reflect.ValueOf(int64(u64)))
	}
	return nil
}

func (d *Decoder) decodeNegative(rv reflect.Value, additional []byte) error {
	u64 := toU64(additional)

	// Check that value fits
	overflows := false
	kind := rv.Kind()
	if kind == reflect.Interface && !rv.IsNil() {
		kind = rv.Elem().Kind()
	}
	switch kind {
	case reflect.Int:
		overflows = len(additional) > (bits.UintSize/8) || int(u64) < 0
	case reflect.Int8:
		overflows = len(additional) > 1 || int8(u64+1) < 0
	case reflect.Int16:
		overflows = len(additional) > 2 || int16(u64+1) < 0
	case reflect.Int32:
		overflows = len(additional) > 4 || int32(u64+1) < 0
	case reflect.Int64:
		overflows = len(additional) > 8 || int64(u64+1) < 0
	default:
		return fmt.Errorf("%w: only primitive int(N) types supported",
			ErrUnsupportedType{typeName: rv.Type().Name()})
	}
	if overflows {
		return fmt.Errorf("%w: value overflows",
			ErrUnsupportedType{typeName: rv.Type().Name()})
	}

	// Note that setting cannot be done with reflect.Value.SetXXX because the
	// reflect.Value may be an interface and its Elem() is not settable.
	switch kind {
	case reflect.Int:
		rv.Set(reflect.ValueOf(-int(u64 + 1)))
	case reflect.Int8:
		rv.Set(reflect.ValueOf(-int8(u64 + 1)))
	case reflect.Int16:
		rv.Set(reflect.ValueOf(-int16(u64 + 1)))
	case reflect.Int32:
		rv.Set(reflect.ValueOf(-int32(u64 + 1)))
	case reflect.Int64:
		rv.Set(reflect.ValueOf(-int64(u64 + 1)))
	}
	return nil
}

func (d *Decoder) decodeByteSlice(rv reflect.Value, additional []byte) error {
	length := toU64(additional)
	bs := make([]byte, length)
	if _, err := d.r.Read(bs); err != nil {
		return fmt.Errorf("error reading byte/text string: %w", err)
	}

	// Note that setting cannot be done with reflect.Value.SetXXX because the
	// reflect.Value may be an interface and its Elem() is not settable.
	switch rv.Interface().(type) {
	case []byte:
		rv.Set(reflect.ValueOf(bs))
	case string:
		rv.Set(reflect.ValueOf(string(bs)))
	default:
		return fmt.Errorf("%w: only string and []byte are supported",
			ErrUnsupportedType{typeName: rv.Type().Name()})
	}
	return nil
}

func (d *Decoder) decodeArray(rv reflect.Value, additional []byte) error {
	kind := rv.Kind()
	if kind == reflect.Interface && !rv.IsNil() {
		kind = rv.Elem().Kind()
	}
	switch kind {
	case reflect.Struct:
		return d.decodeArrayToStruct(rv, additional)
	case reflect.Slice:
		return d.decodeArrayToSlice(rv, additional)
	default:
		return fmt.Errorf("%w: expected a slice or struct type",
			ErrUnsupportedType{typeName: rv.Type().Name()})
	}
}

func (d *Decoder) decodeArrayToStruct(rv reflect.Value, additional []byte) error {
	if rv.Kind() != reflect.Struct {
		return fmt.Errorf("%w: expected a struct type",
			ErrUnsupportedType{typeName: rv.Type().Name()})
	}

	indices := orderAndFilterFields(rv.NumField(), rv.Type().Field)
	for _, i := range indices {
		f := rv.Field(i)
		newVal := reflect.New(f.Type())
		if err := d.Decode(newVal.Interface()); err != nil {
			return fmt.Errorf("error decoding array item %d: %w", i, err)
		}
		f.Set(newVal.Elem())
	}

	return nil
}

func (d *Decoder) decodeArrayToSlice(rv reflect.Value, additional []byte) error {
	// At this point the reflect.Value is either a reflect.Slice or a
	// reflect.Interface. If it is a slice, then it is mutable - it came from a
	// reference. If it is an interface, however, it came from a reference to
	// the interface and the underlying value is not addressable.
	//
	// Unlike maps, which are size-mutable, slices cannot be grown without a
	// reference type (e.g. *[]any) as shown by append returning a new slice,
	// rather than extending it in place.
	//
	// For addressable slices, we can grow them to the correct size. For
	// interface types, we must instead set them to a slice created with the
	// correct size.
	length := int(toU64(additional))
	slice := rv
	switch slice.Kind() {
	case reflect.Slice:
		// Set slice to the correct length
		slice.Grow(length)
		slice.SetLen(length)

	case reflect.Interface:
		slice.Set(reflect.MakeSlice(slice.Elem().Type(), length, length))
		slice = slice.Elem()

	default:
		return fmt.Errorf("%w: expected a slice type",
			ErrUnsupportedType{typeName: rv.Type().Name()})
	}

	// Decode each item into the correctly sized slice
	itemType := slice.Type().Elem()
	for i := 0; i < length; i++ {
		newVal := reflect.New(itemType)
		if err := d.Decode(newVal.Interface()); err != nil {
			return fmt.Errorf("error decoding array item %d: %w", i, err)
		}
		slice.Index(i).Set(newVal.Elem())
	}

	return nil
}

func (d *Decoder) decodeMap(rv reflect.Value, additional []byte) error {
	kind := rv.Kind()
	if kind == reflect.Interface && !rv.IsNil() {
		kind = rv.Elem().Kind()
		rv = rv.Elem()
	}
	if kind != reflect.Map {
		return fmt.Errorf("%w: expected a map type",
			ErrUnsupportedType{typeName: rv.Type().Name()})
	}

	// Clear map
	rmap := rv
	rmap.Clear()

	// Get key-value types
	keyType := rmap.Type().Key()
	valType := rmap.Type().Elem()

	// Iteratively decode each key-value pair
	length := int(toU64(additional))
	for i := 0; i < length; i++ {
		newKey := reflect.New(keyType)
		if err := d.Decode(newKey.Interface()); err != nil {
			return fmt.Errorf("error decoding map key %d: %w", i, err)
		}

		newVal := reflect.New(valType)
		if err := d.Decode(newVal.Interface()); err != nil {
			return fmt.Errorf("error decoding map val %d: %w", i, err)
		}

		rmap.SetMapIndex(newKey.Elem(), newVal.Elem())
	}

	return nil
}

func (d *Decoder) decodeTag(rv reflect.Value, additional []byte) error {
	if _, ok := rv.Interface().(Tag); !ok {
		return fmt.Errorf("%w: expected a cbor.Tag type",
			ErrUnsupportedType{typeName: rv.Type().Name()})
	}

	num := toU64(additional)
	tagged, err := d.decodeRaw()
	if err != nil {
		return fmt.Errorf("error decoding tag %d type: %w", num, err)
	}

	rv.Set(reflect.ValueOf(Tag{
		Number:     num,
		DecodedVal: tagged,
	}))

	return nil
}

func (d *Decoder) decodeSimple(rv reflect.Value, lowFiveBits byte, additional []byte) error {
	switch lowFiveBits {
	case falseVal, trueVal:
		// Note that setting cannot be done with reflect.Value.SetXXX because
		// the reflect.Value may be an interface and its Elem() is not
		// settable.
		kind := rv.Kind()
		if kind == reflect.Interface && !rv.IsNil() {
			kind = rv.Elem().Kind()
		}
		if kind != reflect.Bool {
			return fmt.Errorf("%w: must be a bool",
				ErrUnsupportedType{typeName: rv.Type().Name()})
		}
		rv.Set(reflect.ValueOf(lowFiveBits == trueVal))
	case nullVal, undefinedVal:
		switch {
		case rv.Kind() == reflect.Pointer && rv.IsNil():
			rv.SetZero()
		case rv.Kind() == reflect.Struct && rv.NumField() == 0:
			rv.SetZero()
		default:
			return fmt.Errorf("%w: must be a pointer or empty struct to decode null/undefined",
				ErrUnsupportedType{typeName: rv.Type().Name()})
		}
	case halfFloat, singleFloat, doubleFloat:
		return ErrUnsupportedType{typeName: "decoding float"}
	default:
		if lowFiveBits <= oneByteAdditional {
			return d.decodePositive(rv, additional)
		}
		return ErrUnsupportedType{typeName: "decoding reserved simple value"}
	}
	return nil
}

func (d *Decoder) typeInfo() (highThreeBits, lowFiveBits byte, additional []byte, _ error) {
	var first [1]byte
	if _, err := d.r.Read(first[:]); err != nil {
		return 0, 0, nil, err
	}

	highThreeBits = first[0] >> 5
	lowFiveBits = first[0] & fiveBitMask

	// If the low five bits indicate, read 1, 2, 4, or 8 additional bytes
	switch lowFiveBits {
	case oneByteAdditional:
		additional = make([]byte, 1)
	case twoBytesAdditional:
		additional = make([]byte, 2)
	case fourBytesAdditional:
		additional = make([]byte, 4)
	case eightBytesAdditional:
		additional = make([]byte, 8)
	default:
		return highThreeBits, lowFiveBits, nil, nil
	}

	if n, err := d.r.Read(additional); err != nil {
		return 0, 0, nil, err
	} else if n < len(additional) {
		return 0, 0, nil, fmt.Errorf("read of additional info was short, expected %d bytes, read %d", len(additional), n)
	}
	return highThreeBits, lowFiveBits, additional, nil
}

// Encoder allows for setting encoding options when marshaling CBOR data.
type Encoder struct {
	w io.Writer

	// Future encoding options
}

// NewEncoder returns a new Encoder. The [io.Writer] is not automatically flushed.
func NewEncoder(w io.Writer) *Encoder { return &Encoder{w: w} }

func (e *Encoder) write(b []byte) error {
	_, err := e.w.Write(b)
	return err
}

// Encode CBOR data to the underlying [io.Writer].
func (e *Encoder) Encode(v any) error {
	// Use reflection to dereference pointers, get concrete types out of
	// interfaces, and unwrap named types
	rv := reflect.ValueOf(v)
	for (rv.Kind() == reflect.Pointer && !rv.IsNil()) || rv.Kind() == reflect.Interface {
		// If the value implements Marshaler, use MarshalCBOR
		if m, ok := rv.Interface().(Marshaler); ok {
			b, err := m.MarshalCBOR()
			if err != nil {
				return err
			}
			return e.write(b)
		}
		rv = rv.Elem()
	}
	v = rv.Interface()

	// Dispatch encoding by reflected data type
	switch {
	case rv.CanInt() || rv.CanUint():
		return e.encodeNumber(rv)
	case func() bool { _, ok := v.([]byte); return ok }():
		return e.encodeTextOrBinary(byteStringMajorType, v.([]byte))
	case func() bool { _, ok := v.(Tag); return ok }():
		return e.encodeTag(v.(Tag))
	case rv.Kind() == reflect.String:
		return e.encodeTextOrBinary(textStringMajorType, []byte(v.(string)))
	case rv.Kind() == reflect.Array || rv.Kind() == reflect.Slice:
		return e.encodeArray(rv.Len(), rv.Index, nil)
	case rv.Kind() == reflect.Struct:
		return e.encodeArray(rv.NumField(), rv.Field, rv.Type().Field)
	case rv.Kind() == reflect.Map:
		return e.encodeMap(rv.Len(), rv.MapKeys(), rv.MapIndex)
	case rv.Kind() == reflect.Bool:
		return e.encodeBool(v.(bool))
	case (rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface) && rv.IsNil():
		return e.encodeNull()
	default:
		return ErrUnsupportedType{typeName: rv.Type().String()}
	}
}

// panics if info is not 1, 2, 4, or 8 bytes
func additionalInfo(majorType byte, info []byte) []byte {
	b := (majorType & threeBitMask) << 5
	switch len(info) {
	case 1:
		if info[0] < oneByteAdditional {
			b |= info[0]
			info = nil
		} else {
			b |= oneByteAdditional
		}
	case 2:
		b |= twoBytesAdditional
	case 4:
		b |= fourBytesAdditional
	case 8:
		b |= eightBytesAdditional
	default:
		panic("additionalInfo was not 1, 2, 4, or 8 bytes")
	}
	return append([]byte{b}, info...)
}

// panics if more than 8 bytes given
func toU64(b []byte) uint64 {
	if len(b) > 8 {
		panic("too many bytes to decode into a uint64 without overflowing")
	}
	padded := make([]byte, 8-len(b))
	padded = append(padded, b...)
	return binary.BigEndian.Uint64(padded)
}

func u64Bytes(u64 uint64) []byte {
	// Convert to 8 byte slice
	be := binary.BigEndian.AppendUint64(nil, u64)

	// Drop first 4 bytes if all zero (u64 -> u32)
	if [4]byte(be[:4]) == [4]byte{0x00, 0x00, 0x00, 0x00} {
		be = be[4:]

		// Drop next 2 bytes if all zero (u32 -> u16)
		if [2]byte(be[:2]) == [2]byte{0x00, 0x00} {
			be = be[2:]

			// Drop next 1 byte if zero (u16 -> u8)
			if be[0] == 0x00 {
				be = be[1:]
			}
		}

	}

	return be
}

func (e *Encoder) encodeNumber(rv reflect.Value) error {
	var u64 uint64
	var majorType byte
	switch {
	case rv.CanUint(): // positive uint
		u64, majorType = rv.Uint(), unsignedIntMajorType
	case rv.CanInt() && rv.Int() >= 0: // positive int
		u64, majorType = uint64(rv.Int()), unsignedIntMajorType
	case rv.CanInt() && rv.Int() < 0: // negative int
		u64, majorType = uint64(-rv.Int()-1), negativeIntMajorType
	default:
		return ErrUnsupportedType{typeName: rv.Type().String()}
	}

	return e.write(additionalInfo(majorType, u64Bytes(u64)))
}

func (e *Encoder) encodeTextOrBinary(majorType byte, b []byte) error {
	info := u64Bytes(uint64(len(b)))
	if err := e.write(additionalInfo(majorType, info)); err != nil {
		return err
	}
	return e.write(b)
}

func (e *Encoder) encodeArray(items int, get func(i int) reflect.Value, field func(i int) reflect.StructField) error {
	// Get index and weight of items
	indices := orderAndFilterFields(items, field)

	// Write the length as additional info
	info := u64Bytes(uint64(len(indices)))
	if err := e.write(additionalInfo(arrayMajorType, info)); err != nil {
		return err
	}

	// Write each item
	for _, i := range indices {
		if err := e.Encode(get(i).Interface()); err != nil {
			return err
		}
	}

	return nil
}

func (e *Encoder) encodeMap(length int, keys []reflect.Value, get func(k reflect.Value) reflect.Value) error {
	// Write the length as additional info
	info := u64Bytes(uint64(length))
	if err := e.write(additionalInfo(mapMajorType, info)); err != nil {
		return err
	}

	// Append each key-value pair by encoding key then value
	for _, key := range keys {
		if err := e.Encode(key.Interface()); err != nil {
			return err
		}
		if err := e.Encode(get(key).Interface()); err != nil {
			return err
		}
	}

	return nil
}

func (e *Encoder) encodeTag(tag Tag) error {
	// Write tag number as additional info
	info := u64Bytes(tag.Number)
	if err := e.write(additionalInfo(tagMajorType, info)); err != nil {
		return err
	}

	// Write the enclosed value
	return e.Encode(tag.EncodeVal)
}

func (e *Encoder) encodeBool(truthy bool) error {
	b := simpleMajorType << 5
	if truthy {
		b |= trueVal
	} else {
		b |= falseVal
	}
	return e.write([]byte{b})
}

func (e *Encoder) encodeNull() error {
	b := simpleMajorType << 5
	b |= nullVal
	return e.write([]byte{b})
}

// func (e *Encoder) encodeUndefined() error {
// 	b := simpleMajorType << 5
// 	b |= undefinedVal
// 	return e.write([]byte{b})
// }

// Handle weighting/skipping options in struct tags
func orderAndFilterFields(n int, field func(i int) reflect.StructField) (indices []int) {
	// Collect weights by struct tag and skip fields with "-"
	type widx struct {
		index  int
		weight int
	}
	var weighted []widx
	for i := 0; i < n; i++ {
		weight := 0

		// Field may be nil if ordering the indices of an array rather than a
		// struct
		if field != nil {
			// Skip private fields
			if !field(i).IsExported() {
				continue
			}

			// Extract cbor tag value before the first comma separator (if any)
			tag := field(i).Tag.Get("cbor")
			val, _, _ := strings.Cut(tag, ",")

			// Skip item if it is a struct field and has the tag `cbor:"-"`
			if val == "-" {
				continue
			}

			// Parse weight from string
			weight, _ = strconv.Atoi(val)
		}

		weighted = append(weighted, widx{index: i, weight: weight})
	}

	// Use weights to order indices using the following algorithm:
	//
	// 1. Lowest weight first
	// 2. If more than one value has the same weight, then lowest original index first
	sort.Slice(weighted, func(i, j int) bool {
		if weighted[i].weight == weighted[j].weight {
			return weighted[i].index < weighted[j].index
		}
		return weighted[i].weight < weighted[j].weight
	})

	// Strip weights, leaving only the ordered indices
	for _, x := range weighted {
		indices = append(indices, x.index)
	}
	return indices
}
