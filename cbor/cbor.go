// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cbor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// MaxArrayDecodeLength limits the max size of an array, string, byte slice, or
// map (where each key-value pair counts as two items).
const MaxArrayDecodeLength = 100_000

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

// FlatMarshaler is implemented by types to provide more than one object of an
// array. This is particularly useful in structs to match the behavior of
// embedded struct fields, but with full control, like Marshaler.
//
// FlatMarshaler is used iff the field has a flatN cbor struct tag, i.e.
// `cbor:",flat2"`.
type FlatMarshaler interface {
	// FlatMarshalCBOR encodes CBOR objects to a stream (not wrapped in a CBOR
	// array). The number of objects decoded must match the flatN option of the
	// cbor tag.
	FlatMarshalCBOR(io.Writer) error
}

// FlatUnmarshaler is implemented by types to consume more than one object of
// an array. This is particularly useful in structs to match the behavior of
// embedded struct fields, but with full control, like Unmarshaler.
//
// FlatUnmarshaler is used iff the field has a flatN cbor struct tag, i.e.
// `cbor:",flat2"`.
type FlatUnmarshaler interface {
	// FlatUnmarshalCBOR decodes CBOR objects from a stream (not an array). The
	// number of objects decoded must match the flatN option of the cbor tag.
	FlatUnmarshalCBOR(io.Reader) error
}

func flatN(sf reflect.StructField) (int, bool) {
	_, options, _ := strings.Cut(sf.Tag.Get("cbor"), ",")
	for _, option := range strings.Split(options, ",") {
		if strings.HasPrefix(option, "flat") {
			if option == "flat" {
				return 1, true
			}
			n, err := strconv.Atoi(strings.TrimPrefix(option, "flat"))
			if err != nil {
				panic("invalid cbor struct tag 'flatNNN' option: " + err.Error())
			}
			return n, true
		}
	}
	return 0, false
}

// RawBytes encodes and decodes untransformed. When encoding, it must contain
// valid CBOR.
type RawBytes []byte

// MarshalCBOR implements Marshaler.
func (b RawBytes) MarshalCBOR() ([]byte, error) {
	if b == nil {
		return []byte{}, nil
	}
	return b, nil
}

// UnmarshalCBOR implements Unmarshaler.
func (b *RawBytes) UnmarshalCBOR(p []byte) error { *b = p; return nil }

// Tag is a tagged CBOR type.
type Tag[T any] struct {
	Num uint64 // 0..(2**64)-1
	Val T
}

func (Tag[T]) isTag() {}

// Number returns the underlying Num field and is used to implement the TagData
// interface.
func (t Tag[T]) Number() uint64 { return t.Num }

// Value returns the underlying Val field and is used to implement the TagData
// interface.
func (t Tag[T]) Value() any { return t.Val }

// TagData allows read-only access to a Tag without value type information.
type TagData interface {
	isTag() // no external types can implement a Tag
	Number() uint64
	Value() any
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
	for rv := reflect.ValueOf(v); (rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface) && !rv.IsNil(); rv = rv.Elem() {
		if u, ok := rv.Interface().(Unmarshaler); ok {
			b, err := d.decodeRaw()
			if err != nil {
				_, isOmitEmpty := rv.Interface().(interface{ isOmitEmpty() })
				if errors.Is(err, io.EOF) && isOmitEmpty {
					return nil
				}
				return err
			}

			return u.UnmarshalCBOR(b)
		}
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
	return d.decodeRawVal(highThreeBits, lowFiveBits, additional)
}

func (d *Decoder) decodeRawVal(highThreeBits, lowFiveBits byte, additional []byte) ([]byte, error) {
	head := append([]byte{(highThreeBits << 5) | lowFiveBits}, additional...)

	switch highThreeBits {
	// Types containing only first byte and additional data
	case unsignedIntMajorType, negativeIntMajorType, simpleMajorType:
		return head, nil

	// Types containing a well-known size without decoding nested types
	case byteStringMajorType, textStringMajorType:
		length, err := decodeLen(highThreeBits, lowFiveBits, additional)
		if err != nil {
			return nil, err
		}

		b := make([]byte, length)
		if _, err := io.ReadFull(d.r, b); err != nil {
			return nil, err
		}
		return append(head, b...), nil

	// Types which must be fully decoded to know their size
	case arrayMajorType, mapMajorType:
		length, err := decodeLen(highThreeBits, lowFiveBits, additional)
		if err != nil {
			return nil, err
		}

		decoded := head
		for i := range length {
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

func decodeLen(highThreeBits, lowFiveBits byte, additional []byte) (int, error) {
	length := toU64(additional)
	if lowFiveBits < 0x18 {
		length = uint64(lowFiveBits)
	}
	if highThreeBits == mapMajorType {
		length *= 2
	}
	if length > math.MaxInt || length >= MaxArrayDecodeLength {
		return 0, fmt.Errorf("length exceeds max size: %d", length)
	}
	return int(length), nil
}

// Decode one item into a settable value
//
//nolint:gocyclo // Dispatch will always have naturally high complexity.
func (d *Decoder) decodeVal(rv reflect.Value) error {
	// Read initial bytes
	highThreeBits, lowFiveBits, additional, err := d.typeInfo()
	if err != nil {
		return err
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

		// Check one more time if the type implements Unmarshaler. This check was
		// deferred until memory allocation for the underlying type was done.
		if u, ok := rv.Interface().(Unmarshaler); ok {
			b, err := d.decodeRawVal(highThreeBits, lowFiveBits, additional)
			if err != nil {
				return err
			}
			return u.UnmarshalCBOR(b)
		}

		// Dereference the pointer
		rv = rv.Elem()
	}

	// If the low five bits are 0..23 then use them in additional so that a
	// single additional byte can contain any value 0-255
	if lowFiveBits < 0x18 {
		additional = []byte{lowFiveBits}
	}

	// Dispatch decoding by major type
	switch highThreeBits {
	case unsignedIntMajorType:
		allocateInterface(rv, reflect.TypeOf(int64(0)))
		return d.decodePositive(rv, additional)
	case negativeIntMajorType:
		allocateInterface(rv, reflect.TypeOf(int64(0)))
		return d.decodeNegative(rv, additional)
	case byteStringMajorType:
		allocateInterface(rv, reflect.TypeOf([]byte(nil)))
		return d.decodeByteSlice(rv, additional)
	case textStringMajorType:
		allocateInterface(rv, reflect.TypeOf(""))
		return d.decodeByteSlice(rv, additional)
	case arrayMajorType:
		allocateInterface(rv, reflect.TypeOf([]any(nil)))
		return d.decodeArray(rv, additional)
	case mapMajorType:
		allocateInterface(rv, reflect.TypeOf(map[any]any(nil)))
		return d.decodeMap(rv, additional)
	case tagMajorType:
		allocateInterface(rv, reflect.TypeOf(Tag[RawBytes]{}))
		return d.decodeTag(rv, additional)
	case simpleMajorType:
		if lowFiveBits == falseVal || lowFiveBits == trueVal {
			allocateInterface(rv, reflect.TypeOf(false))
		}
		return d.decodeSimple(rv, lowFiveBits, additional)
	}

	panic("unreachable")
}

// Initialize the memory of a value if it is a nil interface type.
func allocateInterface(maybeUnsetVal reflect.Value, newType reflect.Type) {
	if maybeUnsetVal.Kind() != reflect.Interface || !maybeUnsetVal.IsNil() {
		return
	}

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
	kind := rv.Kind()
	if kind == reflect.Interface && !rv.IsNil() {
		kind = rv.Elem().Kind()
	}
	switch kind {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
	default:
		return fmt.Errorf("%w: only primitive (u)int(N) types supported",
			ErrUnsupportedType{typeName: rv.Type().String()})
	}
	if overflows(u64, kind) {
		return fmt.Errorf("%w: value overflows",
			ErrUnsupportedType{typeName: rv.Type().String()})
	}

	// Note that setting cannot be done with reflect.Value.SetXXX because the
	// reflect.Value may be an interface and its Elem() is not settable.
	newVal := reflect.ValueOf(u64)
	if rv.Kind() == reflect.Interface {
		newVal = newVal.Convert(rv.Elem().Type())
	}
	rv.Set(newVal.Convert(rv.Type()))
	return nil
}

func overflows(u64 uint64, kind reflect.Kind) bool {
	switch kind {
	case reflect.Uint:
		return u64 > math.MaxUint
	case reflect.Uint8:
		return u64 > math.MaxUint8
	case reflect.Uint16:
		return u64 > math.MaxUint16
	case reflect.Uint32:
		return u64 > math.MaxUint32
	case reflect.Uint64:
		return false
	case reflect.Int:
		return u64 > math.MaxInt
	case reflect.Int8:
		return u64 > math.MaxInt8
	case reflect.Int16:
		return u64 > math.MaxInt16
	case reflect.Int32:
		return u64 > math.MaxInt32
	case reflect.Int64:
		return u64 > math.MaxInt64
	}
	panic("programming error - invalid kind for overflow check")
}

func (d *Decoder) decodeNegative(rv reflect.Value, additional []byte) error {
	u64 := toU64(additional)

	// Check that value fits
	kind := rv.Kind()
	if kind == reflect.Interface && !rv.IsNil() {
		kind = rv.Elem().Kind()
	}
	switch kind {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
	default:
		return fmt.Errorf("%w: only primitive int(N) types supported",
			ErrUnsupportedType{typeName: rv.Type().String()})
	}
	if u64 >= -math.MinInt64-1 || overflowsInt(-int64(u64)-1, kind) {
		return fmt.Errorf("%w: value overflows",
			ErrUnsupportedType{typeName: rv.Type().String()})
	}

	// Note that setting cannot be done with reflect.Value.SetXXX because the
	// reflect.Value may be an interface and its Elem() is not settable.
	newVal := reflect.ValueOf(-u64 - 1)
	if rv.Kind() == reflect.Interface {
		newVal = newVal.Convert(rv.Elem().Type())
	}
	rv.Set(newVal.Convert(rv.Type()))
	return nil
}

func overflowsInt(i64 int64, kind reflect.Kind) bool {
	switch kind {
	case reflect.Int:
		return i64 < math.MinInt
	case reflect.Int8:
		return i64 < math.MinInt8
	case reflect.Int16:
		return i64 < math.MinInt16
	case reflect.Int32:
		return i64 < math.MinInt32
	case reflect.Int64:
		return false
	}
	panic("programming error - invalid kind for overflow check")
}

func (d *Decoder) decodeByteSlice(rv reflect.Value, additional []byte) error {
	length := toU64(additional)
	if length > math.MaxInt || length >= MaxArrayDecodeLength {
		return fmt.Errorf("byte array exceeds max size: %d", length)
	}
	bs := make([]byte, length)
	if _, err := io.ReadFull(d.r, bs); err != nil {
		return fmt.Errorf("error reading byte/text string: %w", err)
	}

	// Note that setting cannot be done with reflect.Value.SetXXX because the
	// reflect.Value may be an interface and its Elem() is not settable.
	_, isBytes := rv.Interface().([]byte)
	_, isString := rv.Interface().(string)
	switch {
	case isBytes || (rv.Kind() == reflect.Slice && rv.Type().Elem().Kind() == reflect.Uint8):
		rv.Set(reflect.ValueOf(bs))
		return nil
	case isString || rv.Kind() == reflect.String:
		rv.Set(reflect.ValueOf(string(bs)).Convert(rv.Type()))
		return nil
	}

	// Support fixed-size array
	if rv.Kind() == reflect.Array && rv.Type().Elem().Kind() == reflect.Uint8 {
		// Ensure array is large enough
		if rv.Len() < int(length) {
			return fmt.Errorf("fixed-size array is too small: must be at least length %d", length)
		}

		// Grow decoded byte slice as needed to fit inside fixed array
		rbs := reflect.ValueOf(&bs).Elem()
		if grow := rv.Len() - rbs.Len(); grow > 0 {
			rbs.Grow(grow)
		}
		rbs.SetLen(rv.Len())

		// Convert slice to array and set new values
		newArr := rbs.Convert(rv.Type())
		rv.Set(newArr)

		return nil
	}

	return fmt.Errorf("%w: only strings, byte slices, and fixed-size arrays are supported",
		ErrUnsupportedType{typeName: rv.Type().String()})
}

func (d *Decoder) decodeArray(rv reflect.Value, additional []byte) error {
	kind := rv.Kind()
	if kind == reflect.Interface && !rv.IsNil() {
		kind = rv.Elem().Kind()
	}
	switch kind {
	case reflect.Struct:
		return d.decodeArrayToStruct(rv, additional)
	case reflect.Slice, reflect.Array:
		return d.decodeArrayToSlice(rv, additional)
	default:
		return fmt.Errorf("%w: expected a slice, array, or struct type",
			ErrUnsupportedType{typeName: rv.Type().String()})
	}
}

func (d *Decoder) decodeArrayToStruct(rv reflect.Value, additional []byte) error {
	if rv.Kind() != reflect.Struct {
		return fmt.Errorf("%w: expected a struct type",
			ErrUnsupportedType{typeName: rv.Type().String()})
	}
	length := toU64(additional)
	if length > math.MaxInt || length >= MaxArrayDecodeLength {
		return fmt.Errorf("array exceeds max size: %d", length)
	}

	// Get order of fields and filter out up to one if necessary
	indices, omittable := fieldOrder(rv.NumField(), rv.Type().Field)
	if int(length) != len(indices) {
		omittedOne := false
		for i, idx := range indices {
			if omittable(idx) {
				if omittedOne {
					return fmt.Errorf("%w: unmarshaling to a struct with more than one omittable field is not supported",
						ErrUnsupportedType{typeName: rv.Type().String()})
				}

				omittedOne = true
				indices = slices.Delete(indices, i, i+1)
			}
		}
	}
	if int(length) != len(indices) {
		return fmt.Errorf("%w: struct has an incorrect number of fields: has %d, expected %d",
			ErrUnsupportedType{typeName: rv.Type().String()}, len(indices), length)
	}

	// Decode each item into the appropriate field
	for i, idx := range indices {
		// If the previous index was the same, skip, because FlatUnmarshaler
		// already decoded all of its values. (The duplicate indices are just
		// so the length of the indices slice matches the array size.)
		if i > 0 && slices.Equal(idx, indices[i-1]) {
			continue
		}

		if err := d.decodeStructField(rv, idx); err != nil {
			return err
		}
	}

	return nil
}

func (d *Decoder) decodeStructField(rv reflect.Value, idx []int) error {
	// Allocate any nil embedded struct pointer fields on the index path
	for i := 1; i < len(idx); i++ {
		embed := rv.FieldByIndex(idx[:i])
		// TODO: Handle embedded interfaces?
		if embed.Kind() == reflect.Pointer && embed.IsNil() {
			embed.Set(reflect.New(embed.Type().Elem()))
		}
	}
	f := rv.FieldByIndex(idx)

	// Use FlatUnmarshaler if flatN option is given
	if n, ok := flatN(rv.Type().FieldByIndex(idx)); ok {
		fm, ok := f.Interface().(FlatUnmarshaler)
		if !ok && f.CanAddr() {
			fm, ok = f.Addr().Interface().(FlatUnmarshaler)
		}
		if !ok {
			panic("struct field with cbor flat option must implement FlatUnmarshaler")
		}
		if err := fm.FlatUnmarshalCBOR(d.r); err != nil {
			return fmt.Errorf("error decoding array item %+v (flat %d): %w", idx, n, err)
		}
		return nil
	}

	// Allocate addressable memory for field
	newVal := reflect.New(f.Type())

	// Decode into new value and then set the field
	if err := d.Decode(newVal.Interface()); err != nil {
		return fmt.Errorf("error decoding array item %+v: %w", idx, err)
	}
	f.Set(newVal.Elem())

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
	length := toU64(additional)
	if length > math.MaxInt || length >= MaxArrayDecodeLength {
		return fmt.Errorf("array exceeds max size: %d", length)
	}
	slice := rv
	switch slice.Kind() {
	case reflect.Slice:
		// Set slice to the correct length
		slice.Grow(int(length))
		slice.SetLen(int(length))

	case reflect.Array:
		// Check array is long enough and clear extra elements
		if rv.Len() < int(length) {
			return fmt.Errorf("fixed-size array is too small: must be at least length %d", length)
		}
		zeroVal := reflect.Zero(slice.Type().Elem())
		for i := int(length); i < rv.Len(); i++ {
			slice.Index(i).Set(zeroVal)
		}

	case reflect.Interface:
		slice.Set(reflect.MakeSlice(slice.Elem().Type(), int(length), int(length)))
		slice = slice.Elem()

	default:
		return fmt.Errorf("%w: expected a slice type",
			ErrUnsupportedType{typeName: rv.Type().String()})
	}

	// Decode each item into the correctly sized slice
	itemType := slice.Type().Elem()
	for i := range int(length) {
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
			ErrUnsupportedType{typeName: rv.Type().String()})
	}

	// Create map if needed
	if rv.IsNil() {
		rv.Set(reflect.MakeMap(rv.Type()))
	}

	// Clear map
	rmap := rv
	rmap.Clear()

	// Get key-value types
	keyType := rmap.Type().Key()
	valType := rmap.Type().Elem()

	// Iteratively decode each key-value pair
	length := toU64(additional)
	if length > math.MaxInt || length >= MaxArrayDecodeLength/2 {
		return fmt.Errorf("map exceeds max size: %d", length)
	}
	for i := range int(length) {
		newKey := reflect.New(keyType)
		if err := d.Decode(newKey.Interface()); err != nil {
			return fmt.Errorf("error decoding map key %d: %w", i, err)
		}

		newVal := reflect.New(valType)
		if err := d.Decode(newVal.Interface()); err != nil {
			return fmt.Errorf("error decoding map val %d: %w", i, err)
		}

		actualKeyType := keyType
		if keyType.Kind() == reflect.Interface {
			if !newKey.Elem().Elem().IsValid() {
				return fmt.Errorf("map key cannot be null or undefined")
			}
			actualKeyType = newKey.Elem().Elem().Type()
		}
		if !actualKeyType.Comparable() {
			return fmt.Errorf("map key type (%s) not comparable", actualKeyType.String())
		}
		rmap.SetMapIndex(newKey.Elem(), newVal.Elem())
	}

	return nil
}

func (d *Decoder) decodeTag(rv reflect.Value, additional []byte) error {
	if _, ok := rv.Interface().(TagData); !ok {
		return fmt.Errorf("%w: expected a cbor.Tag type (or interface wrapping it)",
			ErrUnsupportedType{typeName: rv.Type().String()})
	}

	// If the value is an interface wrapping a Tag, then a new struct with
	// addressable fields must be created and set.
	var iface reflect.Value
	if rv.Kind() == reflect.Interface {
		newVal := reflect.New(rv.Elem().Type())
		iface, rv = rv, newVal.Elem()
	}

	// Set number field
	num := toU64(additional)
	numField := rv.FieldByName("Num")
	numField.SetUint(num)

	// Set value field
	valField := rv.FieldByName("Val")
	if err := d.Decode(valField.Addr().Interface()); err != nil {
		return fmt.Errorf("error decoding tag %d type: %w", num, err)
	}

	// When decoding to an interface, set its value to the newly created struct
	if iface.IsValid() {
		iface.Set(rv)
	}

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
				ErrUnsupportedType{typeName: rv.Type().String()})
		}
		rv.Set(reflect.ValueOf(lowFiveBits == trueVal))
	case nullVal, undefinedVal:
		switch {
		case rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface || rv.Kind() == reflect.Slice:
			rv.SetZero()
		case rv.Kind() == reflect.Struct && rv.NumField() == 0:
			rv.SetZero()
		default:
			return fmt.Errorf("%w: must be a pointer, interface, slice, or empty struct to decode null/undefined",
				ErrUnsupportedType{typeName: rv.Type().Name()})
		}
	case halfFloat, singleFloat, doubleFloat:
		return ErrUnsupportedType{typeName: "decoding float"}
	default:
		if lowFiveBits <= oneByteAdditional {
			allocateInterface(rv, reflect.TypeOf(int64(0)))
			return d.decodePositive(rv, additional)
		}
		return ErrUnsupportedType{typeName: "decoding reserved simple value"}
	}
	return nil
}

func (d *Decoder) typeInfo() (highThreeBits, lowFiveBits byte, additional []byte, _ error) {
	var first [1]byte
	if n, err := d.r.Read(first[:]); err != nil && n == 0 { // allows for n=1, err=io.EOF
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

	if _, err := io.ReadFull(d.r, additional); err != nil {
		return 0, 0, nil, err
	}
	return highThreeBits, lowFiveBits, additional, nil
}

// Encoder allows for setting encoding options when marshaling CBOR data.
type Encoder struct {
	w io.Writer

	// MapKeySort is used to determine sort order of map keys for encoding. If
	// none is set, then Core Deterministic (bytewise lexical) encoding is
	// used.
	//
	// The provided function is called with indices 0..len(keys)-1 and
	// marshaled map keys in a random order. The return value is expected to be
	// a "less" function that is used to iteratively sort the indices in place
	// while the marshaled keys remain unmodified.
	MapKeySort func(indices []int, marshaledKeys [][]byte) func(i, j int) bool
}

// NewEncoder returns a new Encoder. The [io.Writer] is not automatically flushed.
func NewEncoder(w io.Writer) *Encoder { return &Encoder{w: w} }

func (e *Encoder) write(b []byte) error {
	_, err := e.w.Write(b)
	return err
}

// Encode CBOR data to the underlying [io.Writer].
//
//nolint:gocyclo // Dispatch will always have naturally high complexity.
func (e *Encoder) Encode(v any) error {
	// Reflection does not keep the underlying value in scope, so this is
	// needed to keep finalizers from running and possibly modifying the value
	// being encoded (such as zeroing secrets).
	defer runtime.KeepAlive(v)

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
	// Encoding nil will result in a zero reflect.Value and Interface will panic
	if rv.IsValid() {
		// Update v with the new value rv describes
		v = rv.Interface()
	}

	// If the value implements Marshaler, use MarshalCBOR
	if m, ok := v.(Marshaler); ok && !holdsNilPtr(v) {
		b, err := m.MarshalCBOR()
		if err != nil {
			return err
		}
		return e.write(b)
	}

	// Dispatch encoding by reflected data type
	switch {
	case func() bool { _, ok := v.(TagData); return ok }():
		return e.encodeTag(v.(TagData))
	case rv.CanInt() || rv.CanUint():
		return e.encodeNumber(rv)
	case rv.Kind() == reflect.String,
		(rv.Kind() == reflect.Array || rv.Kind() == reflect.Slice) && rv.Type().Elem().Kind() == reflect.Uint8:
		return e.encodeTextOrBinary(rv)
	case rv.Kind() == reflect.Array || rv.Kind() == reflect.Slice:
		return e.encodeArray(rv.Len(), rv.Index)
	case rv.Kind() == reflect.Struct:
		return e.encodeStruct(rv.NumField(), rv.FieldByIndex, rv.Type().FieldByIndex)
	case rv.Kind() == reflect.Map:
		return e.encodeMap(rv.Len(), rv.MapKeys(), rv.MapIndex)
	case rv.Kind() == reflect.Bool:
		return e.encodeBool(rv.Bool())
	case (rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface) && rv.IsNil():
		return e.encodeNull()
	case !rv.IsValid():
		return e.encodeNull()
	default:
		return ErrUnsupportedType{typeName: rv.Type().String()}
	}
}

func holdsNilPtr(v any) bool {
	switch rv := reflect.ValueOf(v); rv.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Array, reflect.Chan, reflect.Slice:
		return rv.IsNil()
	default:
		return false
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
	case rv.CanInt():
		if v := rv.Int(); v >= 0 {
			u64, majorType = uint64(v), unsignedIntMajorType
		} else {
			abs := uint64(-v)
			u64, majorType = abs-1, negativeIntMajorType
		}
	default:
		return ErrUnsupportedType{typeName: rv.Type().String()}
	}

	return e.write(additionalInfo(majorType, u64Bytes(u64)))
}

func (e *Encoder) encodeTextOrBinary(rv reflect.Value) error {
	var b []byte
	var majorType byte
	switch rv.Kind() {
	case reflect.String:
		majorType = textStringMajorType
		b = []byte(rv.String())
	case reflect.Slice:
		majorType = byteStringMajorType
		b = rv.Bytes()
	case reflect.Array:
		majorType = byteStringMajorType
		if rv.CanAddr() {
			b = rv.Bytes()
			break
		}

		// Unaddressable arrays cannot be made into slices, so we must create a
		// slice and copy contents into it
		b = make([]byte, rv.Len())
		if n := reflect.Copy(reflect.ValueOf(b), rv); n != rv.Len() {
			panic("array contents were not fully copied into a slice for encoding")
		}
	}

	info := u64Bytes(uint64(len(b)))
	if err := e.write(additionalInfo(majorType, info)); err != nil {
		return err
	}
	return e.write(b)
}

func (e *Encoder) encodeArray(size int, get func(int) reflect.Value) error {
	if size < 0 {
		panic("negative array lengths are invalid")
	}

	// Write the length as additional info
	info := u64Bytes(uint64(size))
	if err := e.write(additionalInfo(arrayMajorType, info)); err != nil {
		return err
	}

	// Write each item
	for i := range size {
		if err := e.Encode(get(i).Interface()); err != nil {
			return err
		}
	}
	return nil
}

func isEmpty(v reflect.Value) bool {
	return v.IsZero() ||
		(v.Kind() == reflect.Slice && v.Len() == 0) ||
		(v.Kind() == reflect.Map && v.Len() == 0) ||
		(v.Kind() == reflect.Array && v.Len() == 0) ||
		(v.Kind() == reflect.Pointer && v.Elem().Kind() == reflect.Array && v.Len() == 0)
}

func (e *Encoder) encodeStruct(size int, get func([]int) reflect.Value, field func([]int) reflect.StructField) error {
	// Get encoding order of fields
	indices, omittable := fieldOrder(size, func(i int) reflect.StructField { return field([]int{i}) })

	// Filter omittable fields which are the zero value for the associated type
	for i, idx := range indices {
		if omittable(idx) && isEmpty(get(idx)) {
			indices = slices.Delete(indices, i, i+1)
		}
	}

	// Write the length as additional info
	info := u64Bytes(uint64(len(indices)))
	if err := e.write(additionalInfo(arrayMajorType, info)); err != nil {
		return err
	}

	// Write each item
	for i, idx := range indices {
		// If the previous index was the same, skip, because FlatMarshaler
		// already encoded all of its values. (The duplicate indices are just
		// so the length of the indices slice matches the array size.)
		if i > 0 && slices.Equal(idx, indices[i-1]) {
			continue
		}

		// Use FlatMarshaler, if available
		if n, ok := flatN(field(idx)); ok {
			rv := get(idx)
			fm, ok := rv.Interface().(FlatMarshaler)
			if !ok && rv.CanAddr() {
				fm, ok = rv.Addr().Interface().(FlatMarshaler)
			}
			if !ok {
				panic("struct field with cbor flat option must implement FlatMarshaler")
			}
			if err := fm.FlatMarshalCBOR(e.w); err != nil {
				return fmt.Errorf("error encoding struct field %+v (flat %d): %w", idx, n, err)
			}
			continue
		}

		if err := e.Encode(get(idx).Interface()); err != nil {
			return fmt.Errorf("error encoding struct field %+v: %w", idx, err)
		}
	}

	return nil
}

func (e *Encoder) encodeMap(length int, keys []reflect.Value, get func(k reflect.Value) reflect.Value) error {
	if length < 0 {
		panic("negative map lengths are invalid")
	}

	// Write the length as additional info
	info := u64Bytes(uint64(length))
	if err := e.write(additionalInfo(mapMajorType, info)); err != nil {
		return err
	}

	// Marhshal all keys
	marshaledKeys := make([][]byte, len(keys))
	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	enc.MapKeySort = e.MapKeySort
	for i, key := range keys {
		buf.Reset()
		if err := enc.Encode(key.Interface()); err != nil {
			return err
		}
		marshaledKeys[i] = bytes.Clone(buf.Bytes())
	}

	// Sort keys deterministically
	lessFn := e.MapKeySort
	if lessFn == nil {
		lessFn = BytewiseLexicalSort
	}
	indices := make([]int, len(keys))
	for i := range keys {
		indices[i] = i
	}
	sort.Slice(indices, lessFn(indices, marshaledKeys))

	// Append each key-value pair by encoding key then value
	for _, i := range indices {
		if err := e.Encode(RawBytes(marshaledKeys[i])); err != nil {
			return err
		}
		if err := e.Encode(get(keys[i]).Interface()); err != nil {
			return err
		}
	}

	return nil
}

func (e *Encoder) encodeTag(tag TagData) error {
	// Write tag number as additional info
	info := u64Bytes(tag.Number())
	if err := e.write(additionalInfo(tagMajorType, info)); err != nil {
		return err
	}

	// Write the enclosed value
	return e.Encode(tag.Value())
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

type weightedField struct {
	index     []int
	weight    int
	omittable bool
}

// Handle weighting/skipping options in struct tags
func fieldOrder(n int, field func(int) reflect.StructField) (indices [][]int, omittable func([]int) bool) {
	// Collect weights by struct tag and skip fields with "-"
	fields := collectFieldWeights(nil, 0, n, field, nil)

	// Use weights to order indices using the following algorithm:
	//
	// 1. Lowest weight first
	// 2. If more than one value has the same weight, then lowest original index first
	sort.Slice(fields, func(i, j int) bool {
		if fields[i].weight != fields[j].weight {
			return fields[i].weight < fields[j].weight
		}
		for k := range len(fields[i].index) {
			if k+1 > len(fields[i].index) || k+1 > len(fields[j].index) {
				panic("programming error - indices to sort cannot be a parent embedded field of another")
			}
			if fields[i].index[k] != fields[j].index[k] {
				return fields[i].index[k] < fields[j].index[k]
			}
		}
		return false // equal - allowed for FlatMarshaler fields which get encoded/decoded n times
	})

	// Strip weights, leaving only the ordered indices
	for _, x := range fields {
		indices = append(indices, x.index)
	}
	return indices, func(idx []int) bool {
		for _, f := range fields {
			if slices.Equal(f.index, idx) {
				return f.omittable
			}
		}
		return false
	}
}

func collectFieldWeights(parents []int, i, upper int, field func(int) reflect.StructField, fields []weightedField) []weightedField {
	if i >= upper {
		return fields
	}
	f := field(i)

	// Skip private fields
	if !f.IsExported() {
		return collectFieldWeights(parents, i+1, upper, field, fields)
	}

	// Extract cbor tag value before the first comma separator (if any)
	tag := f.Tag.Get("cbor")
	val, options, _ := strings.Cut(tag, ",")

	// Skip item if it is a struct field and has the tag `cbor:"-"`
	if val == "-" {
		return collectFieldWeights(parents, i+1, upper, field, fields)
	}

	// Parse weight from string
	weight, _ := strconv.Atoi(val)

	// Check if omittable
	omittable := false
	for _, option := range strings.Split(options, ",") {
		switch option {
		case "omitempty":
			omittable = true
		}
	}

	// Duplicate parents slice, because it might be appended to
	parents = slices.Clone(parents)

	// Return duplicate indices if flat (un)marshaling
	if n, ok := flatN(f); ok {
		for range n {
			fields = append(fields, weightedField{
				index:  append(parents, i),
				weight: weight,
			})
		}
		return collectFieldWeights(parents, i+1, upper, field, fields)
	}

	// Handle embedded fields
	if f.Anonymous {
		switch {
		case f.Type.Kind() == reflect.Struct:
			nested := collectFieldWeights(append(parents, i), 0, f.Type.NumField(), f.Type.Field, nil)
			return collectFieldWeights(parents, i+1, upper, field, append(fields, nested...))
		case f.Type.Kind() == reflect.Pointer && f.Type.Elem().Kind() == reflect.Struct:
			nested := collectFieldWeights(append(parents, i), 0, f.Type.Elem().NumField(), f.Type.Elem().Field, nil)
			return collectFieldWeights(parents, i+1, upper, field, append(fields, nested...))
		default:
			// TODO: Should embedded interfaces be handled differently?
		}
	}

	// Append to field list
	return collectFieldWeights(parents, i+1, upper, field, append(fields, weightedField{
		index:     append(parents, i),
		weight:    weight,
		omittable: omittable,
	}))
}

// OmitEmpty encodes a zero value (zero, empty array, empty byte string, empty
// string, empty map) as zero bytes.
type OmitEmpty[T any] struct{ Val T }

// MarshalCBOR encodes a zero value (zero, empty array, empty byte string,
// empty string, empty map) as zero bytes.
func (o OmitEmpty[T]) MarshalCBOR() ([]byte, error) {
	b, err := Marshal(o.Val)
	if err != nil {
		return nil, err
	}
	if len(b) != 1 {
		return b, nil
	}
	switch b[0] {
	case 0x00, 0x40, 0x60, 0x80, 0xa0:
		return []byte{}, nil
	default:
		return b, nil
	}
}

// UnmarshalCBOR decodes data into its generic typed Val field. Note that
// OmitEmpty is treated specially by the cbor package such that reading zero
// bytes (EOF) will not cause an error.
func (o *OmitEmpty[T]) UnmarshalCBOR(p []byte) error { return Unmarshal(p, &o.Val) }

func (o OmitEmpty[T]) isOmitEmpty() {}

// BytewiseLexicalSort is a map key sorting function. It is the default for an
// `Encoder`.
//
// It is the "new" canonical form whereas length-first is the "old" canonical
// form.
func BytewiseLexicalSort(indices []int, keys [][]byte) func(i, j int) bool {
	return func(i, j int) bool {
		left, right := keys[indices[i]], keys[indices[j]]
		for k := range len(left) {
			if left[k] != right[k] {
				return left[k] < right[k]
			}
		}
		panic("unreachable for valid CBOR map keys")
	}
}
