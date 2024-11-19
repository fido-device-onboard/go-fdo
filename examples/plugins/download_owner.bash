#!/usr/bin/env bash

set -euo pipefail

VERSION=0.0.1
MODULE=fdo.download
NAME=download_owner.bash
CHUNKSIZE=1014

# Internal state
file=
filename=
started=false
index=0
done=false

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
	exit 0
}

function produce() {
	if "$done"; then
		echo "D"
		exit 0
	fi

	if ! "$started"; then
		b64 "K" "active"
		echo "71" # true

		b64 "K" "name"
		b64 "3" "$filename"

		b64 "K" "length"
		echo "1$(wc -c <"$file" | tr -d '[:space:]')"

		b64 "K" "sha-384"
		b64x "2" "$(openssl dgst -sha384 -r "$file" | cut -d' ' -f1)"

		started=true
	fi

	local chunk
	chunk="$(dd if="$file" skip="$index" bs=1 count="$CHUNKSIZE" 2>/dev/null | openssl base64 -A)"
	((index += $(echo -n "$chunk" | openssl base64 -A -d | wc -c)))

	if [ "$chunk" ]; then
		b64 "K" "data"

		# Command
		echo -n "2"
		# Base64 encoded data
		echo -n "$chunk"
		echo
	fi

	echo "Y"
}

function handle() {
	local key
	key="$(base64 -d <<<"$1")"

	case "$key" in
	"active")
		local next
		read -r next
		if [[ "${next::1}" != "7" ]]; then
			error "expected boolean value after key $key"
		fi
		if [[ "${next:1}" != "1" ]]; then
			error "expected $key to have value true"
		fi
		;;

	"done")
		local next
		read -r next
		if [[ "${next::1}" != "1" ]]; then
			error "expected integer value after key $key"
		fi

		local got expected
		got="${next:1}"
		expected="$(wc -c <"$file" | tr -d '[:space:]')"
		if [ "$got" -ne "$expected" ]; then
			error "expected device to read $expected bytes, got $got"
		fi

		done=true
		;;

	*)
		error "unexpected key: $key"
		;;

	esac
}

function main() {
	file="${1:-}"
	filename="${2:-$file}"

	if [[ "$file" == "" ]]; then
		printf "Usage:\n\t%s FILE [NAME]\n" "$NAME" >&2
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
			produce
			;;

		K)
			handle "$data"
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
