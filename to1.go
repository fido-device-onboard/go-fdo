// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

type HelloRV struct {
	Guid     []byte
	ASigInfo *SigInfo
}

type HelloRVAck struct {
	NonceTO1Proof []byte
	ASigInfo      *SigInfo
}

type RVRedirect struct {
	To1dRV       []RVTO2AddrEntry
	To1dTo0dHash Hash
}

type RVTO2AddrEntry struct {
	IPAddress         []byte
	DNSAddress        string
	Port              uint64
	TransportProtocol uint64
}
