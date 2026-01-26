// Package main tests CBOR library behavior for debugging
package main

import (
	"fmt"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

func main() {
	// Test what type CBOR returns for integer 2
	data, _ := cbor.Marshal([]any{2})
	var arr []any
	_ = cbor.Unmarshal(data, &arr)
	fmt.Printf("Type: %T, Value: %v\n", arr[0], arr[0])
}
