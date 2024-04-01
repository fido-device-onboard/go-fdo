module github.com/fido-device-onboard/go-fdo/examples/cmd

go 1.22.0

replace github.com/fido-device-onboard/go-fdo/sqlite => ../../sqlite

replace github.com/fido-device-onboard/go-fdo => ../..

require (
	github.com/fido-device-onboard/go-fdo v0.0.0-00010101000000-000000000000
	github.com/fido-device-onboard/go-fdo/sqlite v0.0.0-00010101000000-000000000000
)

require (
	github.com/ncruces/go-sqlite3 v0.13.0 // indirect
	github.com/ncruces/julianday v1.0.0 // indirect
	github.com/tetratelabs/wazero v1.7.0 // indirect
	golang.org/x/exp v0.0.0-20240325151524-a685a6edb6d8 // indirect
	golang.org/x/sys v0.18.0 // indirect
)
