// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"context"
	"fmt"
	"io"
	"net/url"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// Implement owner service info module for
// https://github.com/fido-alliance/fdo-sim/blob/main/fsim-repository/fdo.wget.md

// WgetCommand implements the fdo.wget owner module.
type WgetCommand struct {
	// Name to download file as
	Name string

	// URL to make GET request to
	URL *url.URL

	// Optional size of download contents in bytes to ensure device receives
	Length int64

	// Optional SHA-384 of contents
	Checksum []byte

	// Internal state
	sent bool
	done bool
}

var _ serviceinfo.OwnerModule = (*WgetCommand)(nil)

// HandleInfo implements serviceinfo.OwnerModule.
func (w *WgetCommand) HandleInfo(ctx context.Context, messageName string, messageBody io.Reader) error {
	switch messageName {
	case "active":
		var deviceActive bool
		if err := cbor.NewDecoder(messageBody).Decode(&deviceActive); err != nil {
			return fmt.Errorf("error decoding message %s: %w", messageName, err)
		}
		if !deviceActive {
			return fmt.Errorf("device service info module is not active")
		}
		return nil

	case "error":
		var msg string
		if err := cbor.NewDecoder(messageBody).Decode(&msg); err != nil {
			return fmt.Errorf("error decoding message %s: %w", messageName, err)
		}
		return fmt.Errorf("device reported error: %s", msg)

	case "done":
		var n int64
		if err := cbor.NewDecoder(messageBody).Decode(&n); err != nil {
			return fmt.Errorf("error decoding message %s: %w", messageName, err)
		}
		if w.Length > 0 && n != w.Length {
			return fmt.Errorf("device downloaded %d bytes, expected %d bytes", n, w.Length)
		}
		w.done = true
		return nil

	default:
		return fmt.Errorf("unsupported message %q", messageName)
	}
}

// ProduceInfo implements serviceinfo.OwnerModule.
func (w *WgetCommand) ProduceInfo(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	if w.sent {
		return false, w.done, nil
	}

	// Marshal message bodies
	trueBody, err := cbor.Marshal(true)
	if err != nil {
		return false, false, err
	}
	nameBody, err := cbor.Marshal(w.Name)
	if err != nil {
		return false, false, err
	}
	urlBody, err := cbor.Marshal(w.URL.String())
	if err != nil {
		return false, false, err
	}

	// Send wget messages
	if err := producer.WriteChunk("active", trueBody); err != nil {
		return false, false, err
	}
	if len(w.Checksum) > 0 {
		messageBody, err := cbor.Marshal(w.Checksum)
		if err != nil {
			return false, false, err
		}
		if err := producer.WriteChunk("sha-384", messageBody); err != nil {
			return false, false, err
		}
	}
	if err := producer.WriteChunk("name", nameBody); err != nil {
		return false, false, err
	}
	if err := producer.WriteChunk("url", urlBody); err != nil {
		return false, false, err
	}

	w.sent = true
	return false, false, nil
}
