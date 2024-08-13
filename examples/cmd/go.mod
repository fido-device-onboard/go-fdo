module github.com/fido-device-onboard/go-fdo/examples/cmd

go 1.23rc2

replace github.com/fido-device-onboard/go-fdo/sqlite => ../../sqlite

replace github.com/fido-device-onboard/go-fdo => ../..

replace github.com/fido-device-onboard/go-fdo/fsim => ../../fsim

require (
	github.com/fido-device-onboard/go-fdo v0.0.0-00010101000000-000000000000
	github.com/fido-device-onboard/go-fdo/fsim v0.0.0-00010101000000-000000000000
	github.com/fido-device-onboard/go-fdo/sqlite v0.0.0-00010101000000-000000000000
)

require (
	github.com/ncruces/go-sqlite3 v0.17.1 // indirect
	github.com/ncruces/julianday v1.0.0 // indirect
	github.com/tetratelabs/wazero v1.7.3 // indirect
	golang.org/x/crypto v0.25.0 // indirect
	golang.org/x/exp v0.0.0-20240325151524-a685a6edb6d8 // indirect
	golang.org/x/sys v0.24.0 // indirect
	lukechampine.com/adiantum v1.1.1 // indirect
)
