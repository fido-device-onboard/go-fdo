// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

// Rendezvous Variables
const (
	RVDevOnly    uint8 = 0
	RVOwnerOnly  uint8 = 1
	RVIPAddress  uint8 = 2
	RVDevPort    uint8 = 3
	RVOwnerPort  uint8 = 4
	RVDns        uint8 = 5
	RVSvCertHash uint8 = 6
	RVClCertHash uint8 = 7
	RVUserInput  uint8 = 8
	RVWifiSsid   uint8 = 9
	RVWifiPw     uint8 = 10
	RVMedium     uint8 = 11
	RVProtocol   uint8 = 12
	RVDelaysec   uint8 = 13
	RVBypass     uint8 = 14
	RVExtRV      uint8 = 15
)

// Rendezvous Protocols
const (
	RVProtRest    uint8 = 0
	RVProtHTTP    uint8 = 1
	RVProtHTTPS   uint8 = 2
	RVProtTCP     uint8 = 3
	RVProtTLS     uint8 = 4
	RVProtCoapTCP uint8 = 5
	RVProtCoapUDP uint8 = 6
)

// Rendezvous Media
const (
	RVMedEth0    uint8 = 0
	RVMedEth1    uint8 = 1
	RVMedEth2    uint8 = 2
	RVMedEth3    uint8 = 3
	RVMedEth4    uint8 = 4
	RVMedEth5    uint8 = 5
	RVMedEth6    uint8 = 6
	RVMedEth7    uint8 = 7
	RVMedEth8    uint8 = 8
	RVMedEth9    uint8 = 9
	RVMedEthAll  uint8 = 20
	RVMedWifi0   uint8 = 10
	RVMedWifi1   uint8 = 11
	RVMedWifi2   uint8 = 12
	RVMedWifi3   uint8 = 13
	RVMedWifi4   uint8 = 14
	RVMedWifi5   uint8 = 15
	RVMedWifi6   uint8 = 16
	RVMedWifi7   uint8 = 17
	RVMedWifi8   uint8 = 18
	RVMedWifi9   uint8 = 19
	RVMedWifiAll uint8 = 21
)

// RvInstruction contains a paired rendezvous variable identifier and value.
type RvInstruction struct {
	Variable uint8
	Value    []byte
}
