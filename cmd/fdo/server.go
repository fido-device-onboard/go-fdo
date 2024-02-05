// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"flag"
	"fmt"
)

var serverFlags = flag.NewFlagSet("server", flag.ContinueOnError)

func init() {
	// TODO: Server flags
}

func server() error {
	return fmt.Errorf("unimplemented")
}
