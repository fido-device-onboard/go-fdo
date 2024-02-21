// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// fdo implements client and server modes.
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

func usage() {
	fmt.Fprintf(os.Stderr, `
Usage:
  fdo [client|server] [--] [options]

Client options:
%s
Server options:
%s`, options(clientFlags), options(serverFlags))
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
		fmt.Fprintln(os.Stderr, err)
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
			fmt.Fprintln(os.Stderr, err)
			usage()
			os.Exit(1)
		}
		if err := client(); err != nil {
			fmt.Fprintf(os.Stderr, "client error: %v\n", err)
			os.Exit(2)
		}
	case "server", "s", "srv":
		if err := serverFlags.Parse(args); err != nil {
			fmt.Fprintln(os.Stderr, err)
			usage()
			os.Exit(1)
		}
		if err := server(); err != nil {
			fmt.Fprintf(os.Stderr, "server error: %v\n", err)
			os.Exit(2)
		}
	default:
		if sub != "" {
			fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", sub)
		}
		usage()
		os.Exit(1)
	}
}
