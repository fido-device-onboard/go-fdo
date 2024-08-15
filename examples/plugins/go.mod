module github.com/fido-device-onboard/go-fdo/examples/plugins

go 1.23.0

replace github.com/fido-device-onboard/go-fdo => ../..

replace github.com/fido-device-onboard/go-fdo/fsim => ../../fsim

require (
	github.com/fido-device-onboard/go-fdo v0.0.0-00010101000000-000000000000
	github.com/fido-device-onboard/go-fdo/fsim v0.0.0-00010101000000-000000000000
)
