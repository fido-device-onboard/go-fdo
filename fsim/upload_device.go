// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"context"
	"crypto/sha512"
	"fmt"
	"io"
	"io/fs"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// Upload implements https://github.com/fido-alliance/fdo-sim/blob/main/fsim-repository/fdo.upload.md
// and should be registered to the "fdo.upload" module.
type Upload struct {
	FS fs.FS

	// Internal state
	needSha bool
}

var _ serviceinfo.DeviceModule = (*Upload)(nil)

// Transition implements serviceinfo.Module.
func (u *Upload) Transition(active bool) error { u.reset(); return nil }

// Receive implements serviceinfo.Module.
func (u *Upload) Receive(ctx context.Context, moduleName, messageName string, messageBody io.Reader, respond func(string) io.Writer, yield func()) error {
	if err := u.receive(moduleName, messageName, messageBody, respond); err != nil {
		u.reset()
		return err
	}
	return nil
}

func (u *Upload) receive(moduleName, messageName string, messageBody io.Reader, respond func(string) io.Writer) error {
	switch messageName {
	case "name":
		var name string
		if err := cbor.NewDecoder(messageBody).Decode(&name); err != nil {
			return err
		}
		return u.upload(name, respond)

	case "need-sha":
		return cbor.NewDecoder(messageBody).Decode(&u.needSha)

	default:
		u.reset()
		return fmt.Errorf("unknown message %s:%s", moduleName, messageName)
	}
}

func (u *Upload) upload(name string, respond func(string) io.Writer) error {
	defer u.reset()

	f, err := u.FS.Open(name)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	stat, err := f.Stat()
	if err != nil {
		return err
	}
	if err := cbor.NewEncoder(respond("length")).Encode(stat.Size()); err != nil {
		return err
	}

	hash := sha512.New384()
	for i := stat.Size(); i > 0; {
		w := io.MultiWriter(respond("data"), hash)
		n, err := io.CopyN(w, f, min(1014, i))
		if err != nil {
			return err
		}
		i -= n
	}

	if !u.needSha {
		return nil
	}
	return cbor.NewEncoder(respond("sha-384")).Encode(hash.Sum(nil))
}

func (u *Upload) reset() { u.needSha = false }
