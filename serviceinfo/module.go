// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package serviceinfo

import "io"

// A Module handles a single service info key's moduleName (key format:
// "moduleName:messageName"). Any service info structs returned should be added
// to the send queue and processed before TO2 completes.
//
// Any error returned will cause an ErrorMessage to be sent and TO2 will fail.
// If a warning should be logged, this must be done within the handler.
type Module interface {
	HandleFSIM(messageName string, info io.Reader, newInfo func(module, message string) io.WriteCloser) error
}

// Handler implements Module to handle incoming service infos.
type Handler func(string, io.Reader, func(string, string) io.WriteCloser) error

var _ Module = (Handler)(nil)

// HandleFSIM handles a received service info.
func (h Handler) HandleFSIM(messageName string, r io.Reader, newInfo func(module, message string) io.WriteCloser) error {
	return h(messageName, r, newInfo)
}
