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
	HandleFSIM(val []byte) (any, error)
}
