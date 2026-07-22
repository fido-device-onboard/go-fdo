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
		// FDO 1.1 TO2 messages
		return TO2Protocol
	case 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91:
		// FDO 2.0 TO2 messages
		return TO2Protocol
	case 255:
		return AnyProtocol
	default:
		return UnknownProtocol
	}
}

// VersionOf returns the FDO version for a given message type. Returns
// Version101 for 1.1 messages, Version200 for 2.0 messages.
func VersionOf(msgType uint8) Version {
	switch msgType {
	case 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91:
		return Version200
	default:
		return Version101
	}
}

// IsTO2Encrypted returns true if the given TO2 message type requires
// session encryption/decryption. This is used by the HTTP transport to
// determine which messages need to be decrypted on receipt and encrypted
// before sending.
//
// FDO 1.1: Messages 65-71 (after ProveDevice, which completes key exchange)
// FDO 2.0: Messages 86-91 (after ProveOVHdr20 + OVNextEntry20, which
// complete key exchange)
func IsTO2Encrypted(msgType uint8) bool {
	// FDO 1.1: SetupDevice(65) through Done2(71)
	if msgType >= TO2SetupDeviceMsgType && msgType <= TO2Done2MsgType {
		return true
	}
	// FDO 2.0: DeviceSvcInfoRdy20(86) through DoneAck20(91)
	if msgType >= TO2DeviceSvcInfoRdy20MsgType && msgType <= TO2DoneAck20MsgType {
		return true
	}
	return false
}

// IsProtocolStart returns true if the given message type starts a new
// protocol session and therefore requires a new token.
func IsProtocolStart(msgType uint8) bool {
	switch msgType {
	case DIAppStartMsgType: // 10
		return true
	case TO0HelloMsgType: // 20
		return true
	case TO1HelloRVMsgType: // 30
		return true
	case TO2HelloDeviceMsgType: // 60 (FDO 1.1)
		return true
	case TO2HelloDeviceProbeMsgType: // 80 (FDO 2.0)
		return true
	default:
		return false
	}
}

// IsProtocolEnd returns true if the given response message type ends a
// protocol session and the token should be invalidated.
func IsProtocolEnd(respType uint8) bool {
	switch respType {
	case DIDoneMsgType: // 13
		return true
	case TO0AcceptOwnerMsgType: // 23
		return true
	case TO1RVRedirectMsgType: // 33
		return true
	case TO2Done2MsgType: // 71 (FDO 1.1)
		return true
	case TO2DoneAck20MsgType: // 91 (FDO 2.0)
		return true
	default:
		return false
	}
}
