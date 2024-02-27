// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

// Rendezvous Variables
const (
	RVDevOnly    RvVar = 0
	RVOwnerOnly  RvVar = 1
	RVIPAddress  RvVar = 2
	RVDevPort    RvVar = 3
	RVOwnerPort  RvVar = 4
	RVDns        RvVar = 5
	RVSvCertHash RvVar = 6
	RVClCertHash RvVar = 7
	RVUserInput  RvVar = 8
	RVWifiSsid   RvVar = 9
	RVWifiPw     RvVar = 10
	RVMedium     RvVar = 11
	RVProtocol   RvVar = 12
	RVDelaysec   RvVar = 13
	RVBypass     RvVar = 14
	RVExtRV      RvVar = 15
)

// RvVar is an FDO RVVariable.
type RvVar uint8

// Rendezvous Protocols
const (
	RVProtRest    RvProt = 0
	RVProtHTTP    RvProt = 1
	RVProtHTTPS   RvProt = 2
	RVProtTCP     RvProt = 3
	RVProtTLS     RvProt = 4
	RVProtCoapTCP RvProt = 5
	RVProtCoapUDP RvProt = 6
)

// RvProt is an RVProtocolValue.
type RvProt uint8

// Rendezvous Media
const (
	RVMedEth0    RvMedium = 0
	RVMedEth1    RvMedium = 1
	RVMedEth2    RvMedium = 2
	RVMedEth3    RvMedium = 3
	RVMedEth4    RvMedium = 4
	RVMedEth5    RvMedium = 5
	RVMedEth6    RvMedium = 6
	RVMedEth7    RvMedium = 7
	RVMedEth8    RvMedium = 8
	RVMedEth9    RvMedium = 9
	RVMedEthAll  RvMedium = 20
	RVMedWifi0   RvMedium = 10
	RVMedWifi1   RvMedium = 11
	RVMedWifi2   RvMedium = 12
	RVMedWifi3   RvMedium = 13
	RVMedWifi4   RvMedium = 14
	RVMedWifi5   RvMedium = 15
	RVMedWifi6   RvMedium = 16
	RVMedWifi7   RvMedium = 17
	RVMedWifi8   RvMedium = 18
	RVMedWifi9   RvMedium = 19
	RVMedWifiAll RvMedium = 21
)

// RvMedium is an RVMediumValue.
type RvMedium uint8

// RvInstruction contains a paired rendezvous variable identifier and value.
type RvInstruction struct {
	Variable RvVar
	Value    []byte `cbor:",omitempty"`
}
