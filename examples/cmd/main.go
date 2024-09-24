// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package main implements client and server modes.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
)

var flags = flag.NewFlagSet("root", flag.ContinueOnError)

var (
	debug bool
)

func init() {
	flags.BoolVar(&debug, "debug", false, "Run subcommand with debug enabled")
	flags.Usage = usage
	clientFlags.Usage = func() {}
	serverFlags.Usage = func() {}
}

func usage() {
	_, _ = fmt.Fprintf(os.Stderr, `
Usage:
  fdo [global_options] [client|server] [--] [options]

Global options:
%s
Client options:
%s
Server options:
%s
Key types:
  - RSA2048RESTR
  - RSAPKCS
  - RSAPSS
  - SECP256R1
  - SECP384R1

Encryption suites:
  - A128GCM
  - A192GCM
  - A256GCM
  - AES-CCM-64-128-128 (not implemented)
  - AES-CCM-64-128-256 (not implemented)
  - COSEAES128CBC
  - COSEAES128CTR
  - COSEAES256CBC
  - COSEAES256CTR

Key exchange suites:
  - DHKEXid14
  - DHKEXid15
  - ASYMKEX2048
  - ASYMKEX3072
  - ECDH256
  - ECDH384
`, options(flags), options(clientFlags), options(serverFlags))
}

func options(flags *flag.FlagSet) string {
	oldOutput := flags.Output()
	defer flags.SetOutput(oldOutput)

	var buf bytes.Buffer
	flags.SetOutput(&buf)
	flags.PrintDefaults()

	return buf.String()
}

func main() {
	if err := flags.Parse(os.Args[1:]); err != nil {
		usage()
		os.Exit(1)
	}

	sub := flags.Arg(0)
	var args []string
	if flags.NArg() > 1 {
		args = flags.Args()[1:]
		if flags.Arg(1) == "--" {
			args = flags.Args()[2:]
		}
	}

	switch sub {
	case "client", "c", "cli":
		if err := clientFlags.Parse(args); err != nil {
			usage()
			os.Exit(1)
		}
		if err := client(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "client error: %v\n", err)
			os.Exit(2)
		}
	case "server", "s", "srv":
		if err := serverFlags.Parse(args); err != nil {
			usage()
			os.Exit(1)
		}
		if err := server(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "server error: %v\n", err)
			os.Exit(2)
		}
	default:
		if sub != "" {
			_, _ = fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", sub)
		}
		usage()
		os.Exit(1)
	}
}
