// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

// HelloRv is message type 30.
type HelloRv struct {
	GUID     GUID
	ASigInfo *SigInfo
}

// HelloRvAck is message type 31.
type HelloRvAck struct {
	NonceTO1Proof []byte
	ASigInfo      *SigInfo
}

// RvRedirect is message type 33.
type RvRedirect struct {
	To1dRV       []RvTO2Addr
	To1dTo0dHash Hash
}

// RvTO2Addr indicates to the device how to connect to the owner service.
type RvTO2Addr struct {
	IPAddress         []byte
	DNSAddress        string
	Port              uint64
	TransportProtocol uint64
}
