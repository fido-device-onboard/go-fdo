module github.com/fido-device-onboard/go-fdo/tpm

go 1.25.0

replace github.com/fido-device-onboard/go-fdo => ../

require (
	github.com/fido-device-onboard/go-fdo v0.0.0-00010101000000-000000000000
	github.com/google/go-tpm v0.9.8
)

require (
	github.com/google/go-tpm-tools v0.4.7 //indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
)
