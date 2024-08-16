// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package cdn implements CBOR Diagnotic Notation.
//
// CBOR is a binary interchange format. To facilitate documentation and
// debugging, and in particular to facilitate communication between entities
// cooperating in debugging, this section defines a simple human-readable
// diagnostic notation. All actual interchange always happens in the binary
// format.
//
// Only base16 notation is support for binary values.
//
//	h'12345678' // supported
//	b32'CI2FM6A' or b64'EjRWeA' // not supported
//
// Example:
//
//	s,_ := cdn.FromCBOR(cborBytes)
//
//	cborbytes, _ := cdn.ToCBOR(s)
package cdn

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// Sentinel errors
var (
	ErrInvalidInput        = errors.New("cdn: unexpected input")
	ErrInvalidEncodingType = errors.New("cdn: invalid encoding type")
)

// FromCBOR re-encodes CBOR bytes as a diagnostic string.
func FromCBOR(c []byte) (string, error) {
	var v any
	if err := cbor.Unmarshal(c, &v); err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}

	var b bytes.Buffer
	if err := encodeValue(&b, v); err != nil {
		return "", err
	}

	return b.String(), nil
}

// ToCBOR marshals a diagnostic string into CBOR.
func ToCBOR(s string) ([]byte, error) {
	v, err := decodeValue(bytes.NewBufferString(s))
	if err != nil {
		return nil, err
	}

	if isEndArrayToken(v) || isEndMapToken(v) || isCommaToken(v) {
		return nil, ErrInvalidInput
	}

	cb, err := cbor.Marshal(v)
	return cb, err
}

func encodeValue(b *bytes.Buffer, v any) error { //nolint:gocyclo
	switch v := v.(type) {
	default:
		return ErrInvalidEncodingType

	case []byte:
		_, _ = b.WriteString("h'")
		_, _ = hex.NewEncoder(b).Write(v)
		_, _ = b.WriteString("'")

	case string:
		d, err := json.Marshal(v)
		if err != nil {
			return err
		}
		_, _ = b.WriteString(string(d))

	case bool:
		d, err := json.Marshal(v)
		if err != nil {
			return err
		}
		_, _ = b.WriteString(string(d))

	case nil:
		_, _ = b.WriteString("null")

	case int64, uint64:
		_, _ = b.WriteString(fmt.Sprintf("%d", v))

	case []interface{}:
		_, _ = b.WriteString("[")
		for index, element := range v {
			if index > 0 {
				_, _ = b.WriteString(", ")
			}
			if err := encodeValue(b, element); err != nil {
				return err
			}
		}
		_, _ = b.WriteString("]")

	case map[interface{}]interface{}:
		_, _ = b.WriteString("{")
		c := 0
		for key, value := range v {
			if c > 0 {
				_, _ = b.WriteString(", ")
			}
			if err := encodeValue(b, key); err != nil {
				return err
			}
			_, _ = b.WriteString(": ")
			if err := encodeValue(b, value); err != nil {
				return err
			}
			c++

		}
		_, _ = b.WriteString("}")

	case cbor.Tag[cbor.RawBytes]:
		_, _ = b.WriteString(strconv.Itoa(int(v.Num)))
		_, _ = b.WriteString("(")

		var val any
		if err := cbor.Unmarshal(v.Val, &val); err != nil {
			return err
		}
		if err := encodeValue(b, val); err != nil {
			return err
		}

		_, _ = b.WriteString(")")
	}

	return nil

}

func decodeValue(rd io.Reader) (any, error) { //nolint:gocyclo
	r := bufio.NewReader(rd)

	if err := discardSpaces(r); err != nil {
		return nil, err
	}

	b, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	if err := r.UnreadByte(); err != nil {
		return nil, err
	}

	switch b {
	case '[':
		return decodeArray(r)
	case '"':
		return decodeString(r)
	case 't':
		return true, decodeTrue(r)
	case 'f':
		return false, decodeFalse(r)
	case 'h':
		return decodeHex(r)
	case '-':
		return decodeSigned(r)
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return maybeDecodeTag(r)(decodeUnsigned(r))
	case '{':
		return decodeMap(r)
	case 'n':
		return nil, decodeNull(r)
	case ',':
		return commaToken{}, skipToken(r)
	case ']':
		return endArrayToken{}, skipToken(r)
	case '}':
		return endMapToken{}, skipToken(r)
	}

	return nil, ErrInvalidInput
}

func decodeNull(r *bufio.Reader) error {
	t := "null"
	b := make([]byte, len(t))
	if _, err := r.Read(b); err != nil {
		return err
	}
	if string(b) != t {
		return ErrInvalidInput
	}
	return nil
}

func decodeTrue(r *bufio.Reader) error {
	t := "true"
	b := make([]byte, len(t))
	if _, err := r.Read(b); err != nil {
		return err
	}
	if string(b) != t {
		return ErrInvalidInput
	}
	return nil
}

func decodeFalse(r *bufio.Reader) error {
	t := "false"
	b := make([]byte, len(t))
	if _, err := r.Read(b); err != nil {
		return err
	}
	if string(b) != t {
		return ErrInvalidInput
	}
	return nil

}

func maybeDecodeTag(r *bufio.Reader) func(uint64, error) (any, error) {
	return func(num uint64, err error) (any, error) {
		if err != nil {
			return nil, err
		}

		// Check if num is the start of a tag by looking for an open paren
		d, err := r.ReadByte()
		if errors.Is(err, io.EOF) {
			return num, nil
		}
		if err != nil {
			return nil, err
		}
		if d != '(' {
			return num, r.UnreadByte()
		}

		return decodeTag(num, r)
	}
}

func decodeTag(num uint64, r *bufio.Reader) (*cbor.Tag[cbor.RawBytes], error) {
	v, err := decodeValue(r)
	if err != nil {
		return nil, err
	}

	b, err := cbor.Marshal(v)
	if err != nil {
		return nil, err
	}

	if err := decodeDelim(r, ')'); err != nil {
		return nil, err
	}

	return &cbor.Tag[cbor.RawBytes]{Num: num, Val: b}, nil
}

func decodeUnsigned(r *bufio.Reader) (uint64, error) {
	var buf bytes.Buffer
	for {
		b, err := r.ReadByte()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, err
		}

		if !isDigit(b) {
			if err := r.UnreadByte(); err != nil {
				return 0, err
			}
			break
		}

		if _, err := buf.WriteString(string(b)); err != nil {
			return 0, err
		}
	}

	return strconv.ParseUint(buf.String(), 10, 64)
}

func decodeSigned(r *bufio.Reader) (int64, error) {
	if _, err := r.ReadString('-'); err != nil {
		return 0, err
	}

	buf := bytes.NewBufferString("-")
	for {
		b, err := r.ReadByte()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, err
		}

		if !isDigit(b) {
			if err := r.UnreadByte(); err != nil {
				return 0, err
			}
			break
		}

		if _, err := buf.WriteString(string(b)); err != nil {
			return 0, err
		}
	}

	return strconv.ParseInt(buf.String(), 10, 64)
}

func decodeString(r *bufio.Reader) (any, error) {
	if _, err := r.ReadString('"'); err != nil {
		return nil, err
	}

	s, err := r.ReadString('"')
	if err != nil {
		return nil, err
	}

	return s[:len(s)-1], nil
}

func decodeHex(r *bufio.Reader) (any, error) {
	prefix, err := r.ReadString('\'')
	if err != nil {
		return nil, err
	}
	if prefix != "h'" {
		return nil, ErrInvalidInput
	}

	s, err := r.ReadString('\'')
	if err != nil {
		return nil, err
	}
	s = s[:len(s)-1]

	return hex.DecodeString(s)
}

func decodeArray(r *bufio.Reader) (any, error) {
	if _, err := r.ReadString('['); err != nil {
		return nil, err
	}

	a := []interface{}{}
	for {
		v, err := decodeValue(r)
		if err != nil {
			return nil, err
		}
		if isEndArrayToken(v) {
			return a, nil
		}

		switch _, isCommaToken := v.(commaToken); {
		case len(a) == 0 && isCommaToken:
			return nil, ErrInvalidInput
		case len(a) > 0 && !isCommaToken:
			return nil, ErrInvalidInput
		case len(a) == 0 && !isCommaToken:
			// use current value
		case len(a) > 0 && isCommaToken:
			// use next value
			if v, err = decodeValue(r); err != nil {
				return nil, err
			}
		}

		a = append(a, v)
	}
}

func decodeMap(r *bufio.Reader) (any, error) { //nolint:gocyclo
	_, err := r.ReadString('{')
	if err != nil {
		return nil, err
	}

	m := make(map[interface{}]interface{})
	for {
		k, err := decodeValue(r)
		if err != nil {
			return nil, err
		}
		if _, isEndMapToken := k.(endMapToken); isEndMapToken {
			return m, nil
		}

		switch _, isCommaToken := k.(commaToken); {
		case len(m) == 0 && isCommaToken:
			return nil, ErrInvalidInput
		case len(m) > 0 && !isCommaToken:
			return nil, ErrInvalidInput
		case len(m) == 0 && !isCommaToken:
			// use current value
		case len(m) > 0 && isCommaToken:
			// use next value
			if k, err = decodeValue(r); err != nil {
				return nil, err
			}
		}

		if err := decodeDelim(r, ':'); err != nil {
			return nil, err
		}

		v, err := decodeValue(r)
		if err != nil {
			return nil, err
		}
		if isEndMapToken(v) || isEndArrayToken(v) || isCommaToken(v) {
			return nil, ErrInvalidInput
		}

		m[k] = v
	}
}

func decodeDelim(r *bufio.Reader, d byte) error {
	if err := discardSpaces(r); err != nil {
		return err
	}

	b, err := r.ReadByte()
	if err != nil {
		return err
	}
	if d != b {
		return ErrInvalidInput
	}

	return nil
}

func skipToken(r *bufio.Reader) error {
	_, err := r.ReadByte()
	return err
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

type commaToken struct{}

func isCommaToken(v any) bool {
	_, ok := v.(commaToken)
	return ok
}

type endArrayToken struct{}

func isEndArrayToken(v any) bool {
	_, ok := v.(endArrayToken)
	return ok
}

type endMapToken struct{}

func isEndMapToken(v any) bool {
	_, ok := v.(endMapToken)
	return ok
}

func discardSpaces(r *bufio.Reader) error {
	for {
		b, err := r.ReadByte()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if !unicode.IsSpace(rune(b)) {
			return r.UnreadByte()
		}
	}

}
