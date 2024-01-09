// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo_test

/*
func TestClient(t *testing.T) {
	// Load device credential
	b, err := os.ReadFile("testdata/DC.bin")
	if err != nil {
		t.Fatal("error opening device credential test data", err)
	}
	var cred fdo.DeviceCredentialBlob
	err = cbor.Unmarshal(b, &cred)
	if err != nil {
		t.Fatal("error loading device credential blob", err)
	}

	client := fdo.Client{
		Transport: &fdo.HttpTransport{},
		Signer:    nil, // TODO: Mock signer
	}

	rv, err := client.TransferOwnership1(context.TODO())
	if err != nil {
		t.Fatal("error performing TO1", err)
	}
}
*/
