// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package protocol contains common protocol-related types and values.
package protocol

// Protocol is the FDO specification-defined protocol.
type Protocol uint8

// Protocol enumeration values
const (
	UnknownProtocol Protocol = iota
	DIProtocol
	TO0Protocol
	TO1Protocol
	TO2Protocol
	AnyProtocol // for error message types
)

func (p Protocol) String() string {
	switch p {
	case DIProtocol:
		return "DI"
	case TO0Protocol:
		return "TO0"
	case TO1Protocol:
		return "TO1"
	case TO2Protocol:
		return "TO2"
	case AnyProtocol:
		return "Any"
	default:
		return "Unknown"
	}
}

// Of returns the protocol a given message type belongs to.
func Of(msgType uint8) Protocol {
	switch msgType {
	case 10, 11, 12, 13:
		return DIProtocol
	case 20, 21, 22, 23:
		return TO0Protocol
	case 30, 31, 32, 33:
		return TO1Protocol
	case 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71:
		return TO2Protocol
	case 255:
		return AnyProtocol
	default:
		return UnknownProtocol
	}
}
