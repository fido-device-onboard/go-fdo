module github.com/fido-device-onboard/go-fdo/sqlite

go 1.25.0

replace github.com/fido-device-onboard/go-fdo => ../

require (
	github.com/fido-device-onboard/go-fdo v0.0.0-00010101000000-000000000000
	github.com/ncruces/go-sqlite3 v0.29.1
)

require (
	github.com/ncruces/julianday v1.0.0 // indirect
	github.com/tetratelabs/wazero v1.9.0 // indirect
	golang.org/x/crypto v0.42.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
)
