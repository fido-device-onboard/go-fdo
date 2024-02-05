// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package main

import "flag"

var clientFlags = flag.NewFlagSet("client", flag.ContinueOnError)

func init() {
	clientFlags.Int("n", 0, "some number")
}

func client() error {
	return nil
}
