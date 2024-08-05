// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package plugin

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"unicode/utf8"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

type command byte

const invalidPluginCommand = '%'

/*
Control Commands

	| Char | Command        | Request Parameter          | Response Parameter      |
	| ---- | -------------- | -------------------------- | ----------------------- |
	| M    | Module Name    |                            | Name (base64 string)    |
	| V    | Module Version |                            | Version (base64 string) |
*/
const (
	cModuleName    command = 'M'
	cModuleVersion command = 'V'
)

/*
Data Commands

	| Char | Command       | Parameter                      |
	| ---- | ------------- | ------------------------------ |
	| D    | Done          |                                |
	| E    | Error         | Description (base64)           |
	| K    | Key           | Message name (base64)          |
	| B    | Break         |                                |
	| Y    | Yield         |                                |
	| 1    | Integer       | Whole number                   |
	| 2    | Bytes         | Binary data (base64)           |
	| 3    | String        | Text data (base64)             |
	| 4    | Array         | (none, followed by data)       |
	| 5    | Map           | (none, followed by data)       |
	| 6    | Tag           | Tag number (next cmd is val)   |
	| 7    | Boolean       | 0 (false), 1 (true)            |
	| 8    | Null          |                                |
	| 9    | End Array/Map |                                |
*/
const (
	dDone          command = 'D'
	dError         command = 'E'
	dKey           command = 'K'
	dBreak         command = 'B'
	dYield         command = 'Y'
	dInt           command = '1'
	dBytes         command = '2'
	dString        command = '3'
	dArray         command = '4'
	dMap           command = '5'
	dTag           command = '6'
	dBool          command = '7'
	dNull          command = '8'
	dEndCollection command = '9'
)

func (c command) Valid() bool {
	switch c {
	case cModuleName, cModuleVersion:
		return true
	case dDone, dError, dKey, dBreak, dYield, dInt, dBytes, dString, dArray, dMap, dTag, dBool, dNull, dEndCollection:
		return true
	default:
		return false
	}
}

func (c command) ValidParamType(param interface{}) bool {
	switch c {
	case cModuleName, cModuleVersion:
		_, isString := param.(string)
		return param == nil || isString
	case dDone, dBreak, dYield, dArray, dMap, dNull, dEndCollection:
		return param == nil
	case dInt, dTag:
		switch param.(type) {
		case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
			return true
		default:
			return false
		}
	case dBool:
		_, isBool := param.(bool)
		return isBool
	case dError, dKey, dString:
		_, isString := param.(string)
		return isString
	case dBytes:
		_, isBytes := param.([]byte)
		return isBytes
	}

	panic("programming error - invalid pluginCommand")
}

func (c command) ParseParam(b []byte) (interface{}, error) { //nolint:gocyclo
	switch c {
	case cModuleName, cModuleVersion:
		if len(b) == 0 {
			return nil, nil
		}
		return base64.StdEncoding.AppendDecode(nil, b)

	case dDone, dBreak, dYield, dArray, dMap, dNull, dEndCollection:
		if len(b) > 0 {
			return nil, fmt.Errorf("[command=%q] parameter must be nil", c)
		}
		return nil, nil

	case dInt:
		if len(b) > 0 && b[0] == '-' {
			return strconv.ParseInt(string(b), 10, 64)
		}
		return strconv.ParseUint(string(b), 10, 64)

	case dTag:
		return strconv.ParseUint(string(b), 10, 64)

	case dBool:
		if len(b) != 1 || (b[0] != '0' && b[0] != '1') {
			return nil, fmt.Errorf("boolean parameter must be 0 or 1")
		}
		return b[0] == '1', nil

	case dError, dKey, dString:
		decoded, err := base64.StdEncoding.AppendDecode(nil, b)
		if err != nil {
			return nil, err
		}
		return string(decoded), nil

	case dBytes:
		return base64.StdEncoding.AppendDecode(nil, b)
	}

	panic("programming error - invalid pluginCommand")
}

type protocol struct {
	in     io.Writer
	out    *bufio.Scanner
	peeked bool
}

func (p *protocol) Send(c command, param interface{}) error {
	// Validate and write command character
	if !c.Valid() {
		return fmt.Errorf("invalid command: %q", c)
	}
	if !c.ValidParamType(param) {
		return fmt.Errorf("invalid parameter [type=%T] for command %q", param, c)
	}
	if _, err := p.in.Write([]byte{byte(c)}); err != nil {
		return err
	}

	switch param := param.(type) {
	case bool:
		val := 0
		if param {
			val = 1
		}
		if _, err := fmt.Fprintln(p.in, val); err != nil {
			return err
		}

	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		if _, err := fmt.Fprintln(p.in, param); err != nil {
			return err
		}

	case string:
		if _, err := base64.NewEncoder(base64.StdEncoding, p.in).Write([]byte(param)); err != nil {
			return err
		}

	case []byte:
		if _, err := base64.NewEncoder(base64.StdEncoding, p.in).Write(param); err != nil {
			return err
		}
	}

	// Write newline
	if _, err := fmt.Fprint(p.in, "\n"); err != nil {
		return err
	}
	return nil
}

func (p *protocol) Peek() (command, []byte, error) {
	// Only read a line if the line hasn't already been peeked at
	if !p.peeked && !p.out.Scan() {
		if err := p.out.Err(); err != nil {
			return invalidPluginCommand, nil, fmt.Errorf("error reading from plugin: %w", err)
		}
		return invalidPluginCommand, nil, fmt.Errorf("plugin exited")
	}

	// Skip empty lines
	line := p.out.Bytes()
	if len(line) == 0 {
		return p.Peek()
	}

	// Parse the command
	c, rest := command(line[0]), line[1:]
	if !c.Valid() {
		return invalidPluginCommand, nil, fmt.Errorf("invalid command: %q", c)
	}

	// Return the command and unparsed line
	p.peeked = true
	return c, rest, nil
}

func (p *protocol) Recv() (command, interface{}, error) {
	c, line, err := p.Peek()
	if err != nil {
		return invalidPluginCommand, nil, err
	}
	p.peeked = false

	param, err := c.ParseParam(line)
	if err != nil {
		return invalidPluginCommand, nil, fmt.Errorf("error parsing parameter for command %q: %w", c, err)
	}

	return c, param, nil
}

var errEndCollection = errors.New("unexpected end of collection command")

func (p *protocol) DecodeValue() (interface{}, error) {
	c, param, err := p.Recv()
	if err != nil {
		return nil, err
	}

	switch c {
	case dInt, dBytes, dString, dBool, dNull:
		return param, nil

	case dTag:
		inner, err := p.DecodeValue()
		if err != nil {
			return nil, err
		}
		return cbor.Tag[any]{
			Num: param.(uint64),
			Val: inner,
		}, nil

	case dArray:
		arr := []interface{}{}
		for {
			next, err := p.DecodeValue()
			if errors.Is(err, errEndCollection) {
				return arr, nil
			}
			if err != nil {
				return nil, err
			}
			arr = append(arr, next)
		}

	case dMap:
		m := map[interface{}]interface{}{}
		for {
			key, err := p.DecodeValue()
			if errors.Is(err, errEndCollection) {
				return m, nil
			}
			if err != nil {
				return nil, err
			}

			val, err := p.DecodeValue()
			if err != nil {
				return nil, err
			}
			m[key] = val
		}

	case dEndCollection:
		return nil, errEndCollection

	default:
		return nil, fmt.Errorf("invalid data: got unexpected command %q while parsing", c)
	}
}

func (p *protocol) EncodeValue(v interface{}) error {
	if v == nil {
		return p.Send(dNull, nil)
	}

	switch t := reflect.TypeOf(v); t.Kind() {
	case reflect.Bool:
		var param int
		if v.(bool) {
			param = 1
		}
		return p.Send(dBool, param)

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return p.Send(dInt, v)

	case reflect.String:
		return p.Send(dString, v)

	case reflect.Slice:
		// Handle byte slice as bytes
		if t.Elem().Kind() == reflect.Uint8 {
			return p.Send(dBytes, v)
		}
		return p.encodeArray(v)

	case reflect.Map:
		return p.encodeMap(v)

	case reflect.Pointer:
		return p.EncodeValue(reflect.ValueOf(v).Elem().Interface())
	}

	panic(fmt.Sprintf("invalid type for encoding to plugin protocol value: %T", v))
}

func (p *protocol) encodeArray(v interface{}) error {
	if err := p.Send(dArray, nil); err != nil {
		return fmt.Errorf("error sending start of array to plugin: %w", err)
	}

	rv := reflect.ValueOf(v)
	for i := 0; i < rv.Len(); i++ {
		if err := p.EncodeValue(rv.Index(i).Interface()); err != nil {
			return fmt.Errorf("index %d: %w", i, err)
		}
	}

	if err := p.Send(dEndCollection, nil); err != nil {
		return fmt.Errorf("error sending end of array to plugin: %w", err)
	}

	return nil
}

func (p *protocol) encodeMap(v interface{}) error {
	if err := p.Send(dMap, nil); err != nil {
		return fmt.Errorf("error sending start of map to plugin: %w", err)
	}

	rv := reflect.ValueOf(v)
	for _, key := range rv.MapKeys() {
		if err := p.EncodeValue(key.Interface()); err != nil {
			return fmt.Errorf("key %v: encoding key: %w", key.Interface(), err)
		}

		val := rv.MapIndex(key)
		if err := p.EncodeValue(val.Interface()); err != nil {
			return fmt.Errorf("key %v: encoding val: %w", key.Interface(), err)
		}
	}

	if err := p.Send(dEndCollection, nil); err != nil {
		return fmt.Errorf("error sending end of map to plugin: %w", err)
	}

	return nil
}

func (p *protocol) ModuleName() (string, error) {
	// Request and receive the module name
	if err := p.Send(cModuleName, nil); err != nil {
		return "", fmt.Errorf("error sending module name command: %w", err)
	}
	c, val, err := p.Recv()
	if c != cModuleName {
		return "", fmt.Errorf("plugin responded incorrectly to module name command: received %q command", c)
	}
	if err != nil {
		return "", fmt.Errorf("error receiving module name response: %w", err)
	}
	name := val.(string) // safe due to internal parsing in Recv()

	// Validate and return module name
	if !utf8.ValidString(name) {
		return "", fmt.Errorf("plugin returned a module name that was not valid UTF-8")
	}
	return string(name), nil
}
