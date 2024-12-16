module github.com/fido-device-onboard/go-fdo/examples

go 1.23.0

replace github.com/fido-device-onboard/go-fdo/sqlite => ../sqlite

replace github.com/fido-device-onboard/go-fdo => ..

replace github.com/fido-device-onboard/go-fdo/fsim => ../fsim

replace github.com/fido-device-onboard/go-fdo/tpm => ../tpm

require (
	github.com/fido-device-onboard/go-fdo v0.0.0-00010101000000-000000000000
	github.com/fido-device-onboard/go-fdo/fsim v0.0.0-00010101000000-000000000000
	github.com/fido-device-onboard/go-fdo/sqlite v0.0.0-00010101000000-000000000000
	github.com/fido-device-onboard/go-fdo/tpm v0.0.0-00010101000000-000000000000
	github.com/google/go-tpm v0.9.2-0.20240920144513-364d5f2f78b9
	github.com/google/go-tpm-tools v0.3.13-0.20230620182252-4639ecce2aba
	hermannm.dev/devlog v0.4.1
)

require (
	github.com/ncruces/go-sqlite3 v0.19.1-0.20241017225339-d6aebe67cc4b // indirect
	github.com/ncruces/julianday v1.0.0 // indirect
	github.com/neilotoole/jsoncolor v0.7.1 // indirect
	github.com/tetratelabs/wazero v1.8.1 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/term v0.27.0 // indirect
)
