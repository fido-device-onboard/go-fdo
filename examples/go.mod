module github.com/fido-device-onboard/go-fdo/examples

go 1.25.0

replace github.com/fido-device-onboard/go-fdo/sqlite => ../sqlite

replace github.com/fido-device-onboard/go-fdo => ..

replace github.com/fido-device-onboard/go-fdo/fsim => ../fsim

replace github.com/fido-device-onboard/go-fdo/tpm => ../tpm

require (
	github.com/fido-device-onboard/go-fdo v0.0.0-00010101000000-000000000000
	github.com/fido-device-onboard/go-fdo/fsim v0.0.0-00010101000000-000000000000
	github.com/fido-device-onboard/go-fdo/sqlite v0.0.0-00010101000000-000000000000
	github.com/fido-device-onboard/go-fdo/tpm v0.0.0-00010101000000-000000000000
	github.com/google/go-tpm v0.9.8
	github.com/google/go-tpm-tools v0.4.7
	github.com/niemeyer/muslnet v0.0.0-20250923220305-4b81d3c72602
	github.com/syumai/workers v0.27.0
	hermannm.dev/devlog v0.6.0
	tinygo.org/x/drivers v0.34.0
)

require (
	github.com/ncruces/go-sqlite3 v0.30.4 // indirect
	github.com/ncruces/julianday v1.0.0 // indirect
	github.com/neilotoole/jsoncolor v0.7.1 // indirect
	github.com/tetratelabs/wazero v1.11.0 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/term v0.38.0 // indirect
)
