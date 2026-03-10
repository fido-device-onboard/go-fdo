module github.com/fido-device-onboard/go-fdo/cred

go 1.25.0

replace github.com/fido-device-onboard/go-fdo => ../

replace github.com/fido-device-onboard/go-fdo/tpm => ../tpm

require (
	github.com/fido-device-onboard/go-fdo v0.0.0-00010101000000-000000000000
	github.com/fido-device-onboard/go-fdo/tpm v0.0.0-00010101000000-000000000000
)

require (
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/go-tpm-tools v0.4.7 // indirect
	golang.org/x/sys v0.39.0 // indirect
)
