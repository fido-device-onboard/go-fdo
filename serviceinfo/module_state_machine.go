// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package serviceinfo

import (
	"context"
)

// ModuleStateMachine is a subset of TO2 session state covering the message
// type 68 and 69 exchange.
//
// ModuleStateMachine specifically handles the owner service's side of the
// service info module implementation, selecting which module to execute next,
// and storing and loading the current module's state.
//
// An example state transition sequence would be:
//
//	NextModule [true] ->
//	---
//	Module [mod1] ->
//	    HandleInfo x N
//	    ProduceInfo
//	?PersistModule [mod1*] ->
//	---
//	Module [mod1*] ->
//	    HandleInfo x N
//	    ProduceInfo
//	?PersistModule [mod1**] ->
//	NextModule [true] ->
//	---
//	Module [mod2] ->
//	    HandleInfo x N
//	    ProduceInfo
//	?PersistModule [mod2*] ->
//	NextModule [false] ->
//	CleanupModules
//
// where each asterisk represents a transformation (prime notation), the triple
// dash represents where a TO2 message 69 is sent and a message 68 is received,
// and the question mark indicates optional interface methods.
type ModuleStateMachine interface {
	// Module returns the current service info module name and implementation,
	// with its most recent state intact.
	//
	// If NextModule has not yet been called, this function should error.
	//
	// This function is called multiple times between calls to NextModule so it
	// must always return an appropriately progressed iterator based on the
	// context.
	Module(context.Context) (name string, module OwnerModule, err error)

	// NextModule progresses the TO2 session to the next service info module.
	// If there are no more modules, it returns false.
	//
	// NextModule is called after devmod (the automatic first service info
	// module) completes, so the first call should prepare the first module.
	// (This pattern is similar to (*bufio.Scanner).Scan().)
	//
	// NextModule is responsible for determining the order of module execution.
	// This allows ModuleStateMachine to represent a finite state machine.
	NextModule(context.Context) (valid bool, err error)

	// CleanupModules cleans up any internal state. When the context expires,
	// all remaining cleanup should be forced (i.e. processes killed) without
	// waiting for graceful exit.
	CleanupModules(context.Context)
}

// ModulePersister is an optional interface which may be implemented by
// ModuleStateMachines.
//
// There are generally three ways to implement a ModuleStateMachine:
//
// 1. Modules are kept in an in-memory data structure and the owner service is
// either limited to one instance or a reverse proxy is aware of TO2 sessions
// and ensures that all messages go to the same instance.
// 2. Modules hold a connection directly to a persistence layer such as a
// database and do not need to be restored with their previous state before
// handling device service info.
// 3. Modules are NOT held in memory and do NOT have a direct connection to a
// persistence layer - likely because they were implemented in a generic way
// that does not assume the existence of a particular type of database with a
// particular schema.
//
// To make option 3 possible - the best option for reusable service info module
// implementations - ModulePersister provides a hook for encoding and storing
// module state after the module has handled device service info and produced
// owner service info but before the TO2 message handler ends.
type ModulePersister interface {
	// PersistModule stores the state of the current module. It is called after
	// an OwnerService's ProduceInfo method is invoked but before the service
	// info is sent in the message 69 response.
	//
	// This method exists so that modules can implement json.Marshaler,
	// encoding.BinaryMarshaler, or similar and the ModuleStateMachine can
	// encode and persist their state without having to rely on the service
	// info module implementation being built to work with a particular
	// database and table schema.
	PersistModule(ctx context.Context, name string, module OwnerModule) error
}
