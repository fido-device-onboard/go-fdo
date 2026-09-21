module github.com/fido-device-onboard/go-fdo/sqlite

go 1.26.0

replace github.com/fido-device-onboard/go-fdo => ../

require (
	github.com/fido-device-onboard/go-fdo v0.0.0-00010101000000-000000000000
	github.com/ncruces/go-sqlite3 v0.35.5
)

require (
	github.com/ncruces/go-sqlite3-wasm/v6 v6.2.35304 // indirect
	github.com/ncruces/julianday v1.0.0 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)
