// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"net"
	"strconv"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

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

// BaseHTTP parses the valid HTTP and HTTPS URLs from the RV directives.
//
//nolint:gocyclo
func BaseHTTP(rvInfo [][]RvInstruction) (to1URLs, to2URLs []string) {
	for _, directive := range rvInfo {
		m := make(map[RvVar][][]byte)
		for _, instruction := range directive {
			m[instruction.Variable] = append(m[instruction.Variable], instruction.Value)
		}

		// Check the protocol is HTTP(S)
		var prot RvProt
		switch protVals := m[RVProtocol]; len(protVals) {
		case 0:
			// default to HTTPS
			prot = RVProtHTTPS
		case 1:
			if err := cbor.Unmarshal(protVals[0], &prot); err != nil {
				// bad protocol
				continue
			}
		default:
			// too many protocols
			continue
		}
		if prot != RVProtHTTP && prot != RVProtHTTPS {
			// non-HTTP(S)
			continue
		}

		// Parse the RV server addr(s)
		var dnsAddrs []string
		for _, dnsAddrVal := range m[RVDns] {
			var dnsAddr string
			if err := cbor.Unmarshal(dnsAddrVal, &dnsAddr); err != nil {
				// must be a string
				continue
			}
			dnsAddrs = append(dnsAddrs, dnsAddr)
		}
		var ipAddrs []net.IP
		for _, ipAddrVal := range m[RVIPAddress] {
			var ipAddr net.IP
			if err := cbor.Unmarshal(ipAddrVal, &ipAddr); err != nil || (ipAddr.To4() == nil && ipAddr.To16() == nil) {
				// must be IPv4 or IPv6
				continue
			}
			ipAddrs = append(ipAddrs, ipAddr)
		}
		var portNum uint16
		switch portVals := m[RVDevPort]; len(portVals) {
		case 0:
			portNum = 443
			if prot == RVProtHTTP {
				portNum = 80
			}
		case 1:
			if err := cbor.Unmarshal(portVals[0], &portNum); err != nil {
				// must be a valid number
				continue
			}
		default:
			// must have 0 or 1 port specified
			continue
		}

		// Construct and collect URLs
		scheme := "https://"
		if prot == RVProtHTTP {
			scheme = "http://"
		}
		port := strconv.Itoa(int(portNum))
		for _, host := range dnsAddrs {
			url := scheme + net.JoinHostPort(host, port)
			if _, rvBypass := m[RVBypass]; rvBypass {
				to2URLs = append(to2URLs, url)
			} else {
				to1URLs = append(to1URLs, url)
			}
		}
		for _, ip := range ipAddrs {
			url := scheme + net.JoinHostPort(ip.String(), port)
			if _, rvBypass := m[RVBypass]; rvBypass {
				to2URLs = append(to2URLs, url)
			} else {
				to1URLs = append(to1URLs, url)
			}
		}
	}

	return to1URLs, to2URLs
}
