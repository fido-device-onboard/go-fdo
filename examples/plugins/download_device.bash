#!/usr/bin/env bash

set -euo pipefail

VERSION=0.0.1
MODULE=fdo.download
NAME=download_device.bash

# Internal state
dir=
file=
name=
length=
checksum=

function cleanup() {
	if [ "$file" ]; then rm "$file" || true; fi
	file=
	name=
	length=
	checksum=
}

# Write line with command char and base64 data
function b64() {
	local command data
	command="${1}"
	data="${2:-}"

	echo -n "$command"
	echo -n "$data" | openssl base64 -A
	echo
}

function error() {
	b64 "E" "$1"
	cleanup
}

function yield() {
	if [ ! "$file" ] || [ ! "$length" ]; then
		# continue to wait for name/length/checksum
		return
	fi

	local bytecount
	bytecount="$(wc -c <"$file" | tr -d '[:space:]')"
	if [ "$bytecount" -lt "$length" ]; then
		# continue to wait for data
		return
	fi

	if [ "$bytecount" -gt "$length" ]; then
		>&2 echo "received too much data for file $name"
		>&2 echo "expected $length"
		>&2 echo "     got $bytecount"
		return 1
	fi

	if [ "$checksum" ]; then
		local gotsum
		gotsum="$(openssl dgst -sha384 -r "$file" | cut -d' ' -f1)"
		if [ "$gotsum" != "$checksum" ]; then
			>&2 echo "mismatched checksums for file $name"
			>&2 echo "expected $checksum"
			>&2 echo "     got $gotsum"
			return 1
		fi
	fi

	# rename temp file to final location
	if ! mv "$file" "$dir/$name"; then
		return 1
	fi

	# success
	b64 "K" "done"
	printf "1%s\n" "$bytecount"
	cleanup
}

function handle() {
	local key
	key="$(openssl base64 -A -d <<<"$1")"

	case "$key" in
	"name")
		local next
		read -r next
		if [[ "${next::1}" != "3" ]]; then
			error "expected string value after key $key"
		fi
		name="$(openssl base64 -A -d <<<"${next:1}")"
		file="$(mktemp -p "$dir")"
		;;

	"length")
		local next
		read -r next
		if [[ "${next::1}" != "1" ]]; then
			error "expected integer value after key $key"
		fi
		length="${next:1}"
		;;

	"sha-384")
		local next
		read -r next
		if [[ "${next::1}" != "2" ]]; then
			error "expected byte array value after key $key"
		fi
		checksum="$(openssl base64 -d <<<"${next:1}" | xxd -p -c 0 | tr -d '\n')"
		;;

	"data")
		local next
		read -r next
		if [[ "${next::1}" != "2" ]]; then
			error "expected byte array value after key $key"
		fi

		base64 -d <<<"${next:1}" >>"$file"
		;;

	*)
		error "unexpected key: $key"
		;;

	esac
}

function main() {
	dir="${1:-.}"

	if [[ "$dir" == "-h" ]]; then
		printf "Usage:\n\t%s [DIR]\n" "$NAME" >&2
		exit 1
	fi

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
			if ! yield; then
				b64 "K" "done"
				echo "1-1" # -1 indicates an error
			fi
			echo "Y"
			;;

		K)
			handle "$data"
			;;

		E)
			cleanup
			;;

		*)
			error "invalid command received: $command"
			;;

		esac
	done
}

main "$@"
