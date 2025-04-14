// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package protocol

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"

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
	RVMedEthAll  uint8 = 20
	RVMedWifiAll uint8 = 21
)

// RvInstruction contains a paired rendezvous variable identifier and value.
type RvInstruction struct {
	Variable RvVar
	Value    []byte `cbor:",omitempty"`
}

// RvTO2Addr indicates to the device how to connect to the owner service.
type RvTO2Addr struct {
	IPAddress         *net.IP // Can be null, unless DNSAddress is null
	DNSAddress        *string // Can be null, unless IPAddress is null
	Port              uint16
	TransportProtocol TransportProtocol
}

func (a RvTO2Addr) String() string {
	var addr string
	if a.DNSAddress != nil {
		addr = *a.DNSAddress
	} else if a.IPAddress != nil {
		addr = a.IPAddress.String()
	}
	if a.Port > 0 {
		port := strconv.Itoa(int(a.Port))
		addr = net.JoinHostPort(addr, port)
	}
	return fmt.Sprintf("%s://%s", a.TransportProtocol, addr)
}

// To1d is a "blob" that indicates a network address (RVTO2Addr) where the
// Device can find a prospective Owner for the TO2 Protocol.
type To1d struct {
	RV       []RvTO2Addr
	To0dHash Hash
}

func (to1d To1d) String() string {
	s := "to1d[\n"
	s += "  RV:\n"
	for _, addr := range to1d.RV {
		s += "    - " + addr.String() + "\n"
	}
	s += "  To0dHash:\n"
	s += "    Algorithm: " + to1d.To0dHash.Algorithm.String() + "\n"
	s += "    Value: " + hex.EncodeToString(to1d.To0dHash.Value) + "\n"
	return s + "]"
}

// RvDirective is a fully parsed group of instructions.
type RvDirective struct {
	// Addresses

	URLs   []*url.URL
	Bypass bool

	// Network interface configuration

	EthIface  *uint8 // 20 means try all
	WlanIface *uint8 // 21 means try all
	WlanSSID  string
	WlanPass  string

	// External RV (see 3.7.1 Rendezvous Bypass)

	ExtMechanism string // first element of RVExtRv array
	ExtArguments []byte // remaining elements of RVExtRv array (CBOR-encoded)

	// Other

	Delay      time.Duration
	ServerCert *Hash
	ServerCA   *Hash
}

// ParseDeviceRvInfo parses all directives for a device.
func ParseDeviceRvInfo(rvInfo [][]RvInstruction) []RvDirective {
	directives := make([]RvDirective, len(rvInfo))
	for i, vars := range rvInfo {
		dir := parseDirective(vars, true)
		if dir == nil {
			continue
		}
		directives[i] = *dir
	}
	return directives
}

// ParseOwnerRvInfo parses all directives for an owner service.
func ParseOwnerRvInfo(rvInfo [][]RvInstruction) []RvDirective {
	directives := make([]RvDirective, len(rvInfo))
	for i, vars := range rvInfo {
		dir := parseDirective(vars, false)
		if dir == nil {
			continue
		}
		directives[i] = *dir
	}
	return directives
}

func parseDirective(vars []RvInstruction, device bool) *RvDirective { //nolint:gocyclo
	dir := RvDirective{
		URLs: parseURLs(vars, device),
	}

	// By spec there should be no more than one variable of each type
	for _, v := range vars {
		switch v.Variable {
		case RVDevOnly:
			if !device {
				return nil
			}

		case RVOwnerOnly:
			if device {
				return nil
			}

		case RVBypass:
			dir.Bypass = true

		case RVMedium:
			var medium uint8
			if err := cbor.Unmarshal(v.Value, &medium); err == nil {
				switch {
				case medium < 10:
					dir.EthIface = &medium
				case medium < 20:
					medium -= 10
					dir.WlanIface = &medium
				case medium == RVMedEthAll:
					dir.EthIface = &medium
				case medium == RVMedWifiAll:
					dir.WlanIface = &medium
				}
			}

		case RVWifiSsid:
			var ssid string
			if err := cbor.Unmarshal(v.Value, &ssid); err == nil {
				dir.WlanSSID = ssid
			}

		case RVWifiPw:
			var pass string
			if err := cbor.Unmarshal(v.Value, &pass); err == nil {
				dir.WlanPass = pass
			}

		case RVExtRV:
			mech, args := cbor.ArrayShift(v.Value)
			if len(mech) > 0 {
				if err := cbor.Unmarshal(mech, &dir.ExtMechanism); err == nil {
					dir.ExtArguments = args
				}
			}

		case RVDelaysec:
			var secs time.Duration
			if err := cbor.Unmarshal(v.Value, &secs); err == nil {
				dir.Delay = secs * time.Second
			}

		case RVSvCertHash:
			var hash Hash
			if err := cbor.Unmarshal(v.Value, &hash); err == nil {
				dir.ServerCert = &hash
			}

		case RVClCertHash:
			var hash Hash
			if err := cbor.Unmarshal(v.Value, &hash); err == nil {
				dir.ServerCA = &hash
			}
		}
	}

	return &dir
}

func parseURLs(vars []RvInstruction, device bool) (urls []*url.URL) { //nolint:gocyclo
	// Collect URL info
	scheme, port := "tls", ""
	var dnsAddr string
	var ipAddr net.IP
	for _, v := range vars {
		switch v.Variable {
		case RVProtocol:
			var proto uint8
			if err := cbor.Unmarshal(v.Value, &proto); err == nil {
				switch proto {
				case RVProtRest:
					// Unsupported, use default
				case RVProtHTTP:
					scheme, port = "http", "80"
				case RVProtHTTPS:
					scheme, port = "https", "443"
				case RVProtTCP:
					scheme = "tcp"
				case RVProtTLS:
					scheme = "tls"
				case RVProtCoapTCP:
					scheme, port = "coap+tcp", "5683"
				case RVProtCoapUDP:
					scheme, port = "coap", "5683"
				}
			}

		case RVDevPort, RVOwnerPort:
			if (device && v.Variable != RVDevPort) || (!device && v.Variable != RVOwnerPort) {
				continue
			}

			var portU16 uint16
			if err := cbor.Unmarshal(v.Value, &portU16); err == nil {
				port = strconv.Itoa(int(portU16))
			}

		case RVDns:
			_ = cbor.Unmarshal(v.Value, &dnsAddr)

		case RVIPAddress:
			_ = cbor.Unmarshal(v.Value, &ipAddr)
		}
	}

	// Assemble URLs
	if dnsAddr != "" {
		host := dnsAddr
		if port != "" {
			host = net.JoinHostPort(host, port)
		}
		urls = append(urls, &url.URL{
			Scheme: scheme,
			Host:   host,
		})
	}
	if len(ipAddr) > 0 {
		host := ipAddr.String()
		if port != "" {
			host = net.JoinHostPort(host, port)
		}
		urls = append(urls, &url.URL{
			Scheme: scheme,
			Host:   host,
		})
	}

	return urls
}
