module github.com/fido-device-onboard/go-fdo/sqlite

go 1.25.0

replace github.com/fido-device-onboard/go-fdo => ../

require (
	github.com/fido-device-onboard/go-fdo v0.0.0-00010101000000-000000000000
	github.com/ncruces/go-sqlite3 v0.34.1
)

require (
	github.com/ncruces/go-sqlite3-wasm/v2 v2.2.35301 // indirect
	github.com/ncruces/julianday v1.0.0 // indirect
	golang.org/x/crypto v0.51.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
)
