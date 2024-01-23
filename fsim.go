// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import "github.com/fido-device-onboard/go-fdo/cbor"

// ServiceInfo is a ServiceInfoKV structure.
type ServiceInfo struct {
	Key string
	Val cbor.Bstr[cbor.RawBytes]
}

// ServiceInfoModule handles a single ServiceInfo key (format:
// "moduleName:messageName").
type ServiceInfoModule interface {
	HandleFSIM(key string, val []byte) (any, error)
}

// FSIMHandler implements ServiceInfoModule to handle incoming service infos.
type FSIMHandler func(key string, val []byte) (any, error)

var _ ServiceInfoModule = (FSIMHandler)(nil)

// HandleFSIM handles a received service info.
func (h FSIMHandler) HandleFSIM(key string, val []byte) (any, error) {
	return h(key, val)
}
