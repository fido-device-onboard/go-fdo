module github.com/fido-device-onboard/go-fdo/tpm

go 1.23.0

replace github.com/fido-device-onboard/go-fdo => ../

require (
	github.com/fido-device-onboard/go-fdo v0.0.0-00010101000000-000000000000
	github.com/google/go-tpm v0.9.2-0.20240920144513-364d5f2f78b9
)

require (
	github.com/google/go-tpm-tools v0.3.13-0.20230620182252-4639ecce2aba // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
)
