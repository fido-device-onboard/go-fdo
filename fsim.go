// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"io"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// ServiceInfo is a ServiceInfoKV structure.
type ServiceInfo struct {
	Key string
	Val cbor.Bstr[cbor.RawBytes]
}

// ServiceInfoModule handles a single service info key's moduleName (key format:
// "moduleName:messageName"). Any service info structs returned should be added
// to the send queue and processed before TO2 completes.
//
// Any error returned will cause an ErrorMessage to be sent and TO2 will fail.
// If a warning should be logged, this must be done within the handler.
type ServiceInfoModule interface {
	HandleFSIM(messageName string, info io.Reader, newInfo func(module, message string) io.WriteCloser) error
}

// FSIMHandler implements ServiceInfoModule to handle incoming service infos.
type FSIMHandler func(string, io.Reader, func(string, string) io.WriteCloser) error

var _ ServiceInfoModule = (FSIMHandler)(nil)

// HandleFSIM handles a received service info.
func (h FSIMHandler) HandleFSIM(messageName string, r io.Reader, newInfo func(module, message string) io.WriteCloser) error {
	return h(messageName, r, newInfo)
}
