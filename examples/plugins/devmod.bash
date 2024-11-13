#!/usr/bin/env bash

set -euo pipefail

VERSION=0.0.1
MODULE=devmod
NAME=devmod.bash

# Internal state
os=
arch=
version=
device=
sn=
pathsep=
sep=
nl=
tmp=
dir=
progenv=
bin=
mudurl=

# Write line with command char and base64 data
function b64() {
	local command data
	command="${1}"
	data="${2:-}"

	echo -n "$command"
	echo -n "$data" | openssl base64 -A
	echo
}

# b64 but from hex input (necessary to allow null bytes in binary input)
function b64x() {
	local command data
	command="${1}"
	data="${2:-}"

	echo -n "$command"
	xxd -r -p <<<"$data" | openssl base64 -A
	echo
}

function error() {
	b64 "E" "$1"
	cleanup
}

function yield() {
	b64 "K" "os"
	b64 "3" "$os"

	b64 "K" "arch"
	b64 "3" "$arch"

	b64 "K" "version"
	b64 "3" "$version"

	b64 "K" "device"
	b64 "3" "$device"

	if [ "$sn" ]; then
		b64 "K" "sn"
		b64x "2" "$sn"
	fi

	if [ "$pathsep" ]; then
		b64 "K" "pathsep"
		b64 "3" "$pathsep"
	fi

	b64 "K" "sep"
	b64 "3" "$sep"

	if [ "$nl" ]; then
		b64 "K" "nl"
		b64 "3" "$nl"
	fi

	if [ "$tmp" ]; then
		b64 "K" "tmp"
		b64 "3" "$tmp"
	fi

	if [ "$dir" ]; then
		b64 "K" "dir"
		b64 "3" "$dir"
	fi

	if [ "$progenv" ]; then
		b64 "K" "progenv"
		b64 "3" "$progenv"
	fi

	b64 "K" "bin"
	b64 "3" "$bin"

	if [ "$mudurl" ]; then
		b64 "K" "mudurl"
		b64 "3" "$mudurl"
	fi

	echo "Y"
}

function main() {
	if [[ "${1:-}" == "-h" ]]; then
		printf "Usage:\n\t%s\n" "$NAME" >&2
		exit 1
	fi

	os="${1:-}"
	arch="${2:-}"
	version="${3:-}"
	device="${4:-}"
	sn="${5:-}"
	pathsep="${6:-}"
	sep="${7:-}"
	nl="${8:-}"
	tmp="${9:-}"
	dir="${10:-}"
	progenv="${11:-}"
	bin="${12:-}"
	mudurl="${13:-}"

	local line
	while read -r line; do
		local command data
		command="${line::1}"
		data="${line:1}"

		case "$command" in
		"")
			# Ignore empty lines
			;;

		M)
			b64 "M" "$MODULE"
			;;

		V)
			b64 "V" "$VERSION"
			;;

		Y)
			yield
			;;

		K)
			error "devmod should not receive service info from owner"
			;;

		E)
			exit 0
			;;

		*)
			error "invalid command received: $command"
			;;

		esac
	done
}

main "$@"
