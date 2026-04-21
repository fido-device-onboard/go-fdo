// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package protocol

// DI Message Types
const (
	DIAppStartMsgType       uint8 = 10
	DISetCredentialsMsgType uint8 = 11
	DISetHmacMsgType        uint8 = 12
	DIDoneMsgType           uint8 = 13
)

// TO0 Message Types
const (
	TO0HelloMsgType       uint8 = 20
	TO0HelloAckMsgType    uint8 = 21
	TO0OwnerSignMsgType   uint8 = 22
	TO0AcceptOwnerMsgType uint8 = 23
)

// TO1 Message Types
const (
	TO1HelloRVMsgType    uint8 = 30
	TO1HelloRVAckMsgType uint8 = 31
	TO1ProveToRVMsgType  uint8 = 32
	TO1RVRedirectMsgType uint8 = 33
)

// TO2 Message Types (FDO 1.01)
const (
	TO2HelloDeviceMsgType            uint8 = 60
	TO2ProveOVHdrMsgType             uint8 = 61
	TO2GetOVNextEntryMsgType         uint8 = 62
	TO2OVNextEntryMsgType            uint8 = 63
	TO2ProveDeviceMsgType            uint8 = 64
	TO2SetupDeviceMsgType            uint8 = 65
	TO2DeviceServiceInfoReadyMsgType uint8 = 66
	TO2OwnerServiceInfoReadyMsgType  uint8 = 67
	TO2DeviceServiceInfoMsgType      uint8 = 68
	TO2OwnerServiceInfoMsgType       uint8 = 69
	TO2DoneMsgType                   uint8 = 70
	TO2Done2MsgType                  uint8 = 71
)

// TO2 Message Types (FDO 2.0)
// Note: In 2.0, device proves itself BEFORE owner proves ownership (anti-DoS)
const (
	TO2HelloDeviceProbeMsgType   uint8 = 80 // Device initiates, can negotiate version
	TO2HelloDeviceAck20MsgType   uint8 = 81 // Server ack with challenge
	TO2ProveDevice20MsgType      uint8 = 82 // Device proves itself FIRST
	TO2ProveOVHdr20MsgType       uint8 = 83 // Owner proves after device verified
	TO2GetOVNextEntry20MsgType   uint8 = 84
	TO2OVNextEntry20MsgType      uint8 = 85
	TO2DeviceSvcInfoRdy20MsgType uint8 = 86
	TO2SetupDevice20MsgType      uint8 = 87
	TO2DeviceSvcInfo20MsgType    uint8 = 88
	TO2OwnerSvcInfo20MsgType     uint8 = 89
	TO2Done20MsgType             uint8 = 90
	TO2DoneAck20MsgType          uint8 = 91
)
