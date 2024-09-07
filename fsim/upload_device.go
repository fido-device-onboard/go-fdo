// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
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

// Transition implements serviceinfo.DeviceModule.
func (u *Upload) Transition(active bool) error { u.reset(); return nil }

// Receive implements serviceinfo.DeviceModule.
func (u *Upload) Receive(ctx context.Context, messageName string, messageBody io.Reader, respond func(string) io.Writer, yield func()) error {
	if err := u.receive(messageName, messageBody, respond, yield); err != nil {
		u.reset()
		return err
	}
	return nil
}

func (u *Upload) receive(messageName string, messageBody io.Reader, respond func(string) io.Writer, yield func()) error {
	switch messageName {
	case "name":
		var name string
		if err := cbor.NewDecoder(messageBody).Decode(&name); err != nil {
			return err
		}
		if err := u.upload(name, respond, yield); err != nil {
			return fmt.Errorf("error uploading %q: %w", name, err)
		}
		return nil

	case "need-sha":
		return cbor.NewDecoder(messageBody).Decode(&u.needSha)

	default:
		u.reset()
		return fmt.Errorf("unknown message %s", messageName)
	}
}

func (u *Upload) upload(name string, respond func(string) io.Writer, yield func()) error {
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
	yield()

	chunk := make([]byte, 1014)
	hash := sha512.New384()
	for i := stat.Size(); i > 0; {
		n, err := f.Read(chunk[:min(1014, i)])
		if err != nil {
			return err
		}
		i -= int64(n)

		if _, err := hash.Write(chunk[:n]); err != nil {
			return err
		}

		if err := cbor.NewEncoder(respond("data")).Encode(chunk[:n]); err != nil {
			return err
		}
		yield()
	}

	if !u.needSha {
		return nil
	}
	return cbor.NewEncoder(respond("sha-384")).Encode(hash.Sum(nil))
}

func (u *Upload) reset() { u.needSha = false }

// Yield implements DeviceModule.
func (u *Upload) Yield(ctx context.Context, respond func(message string) io.Writer, yield func()) error {
	return nil
}
