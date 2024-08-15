#!/usr/bin/env bash

set -euo pipefail

VERSION=0.0.1
MODULE=fdo.download
NAME=download.bash
CHUNKSIZE=1014

# Internal state
file=
produced=false
done=false

function b64() {
	local command data
	command="${1}"
	data="${2:-}"

	echo -n "$command"
	echo -n "${data}" | base64 -w 0
	echo
}

function error() {
	b64 "E" "$1"
	exit 0
}

function produce() {
	if ! "$produced"; then
		b64 "K" "active"
		echo "71" # true

		b64 "K" "name"
		b64 "3" "$file"

		b64 "K" "length"
		echo "1$(wc -c <"$file")"

		b64 "K" "sha-384"
		b64 "2" "$(sha384sum "$file" | cut -d' ' -f1 | xxd -r -p)"

		local char chunk
		while read -r -N 1 char; do
			chunk+="$char"
			if [ "$(wc -c <<<"$chunk")" -eq "$CHUNKSIZE" ]; then
				b64 "K" "data"
				b64 "2" "$chunk"
				chunk=
			fi
		done <"$file"
		if [ "$chunk" ]; then
			b64 "K" "data"
			b64 "2" "$chunk"
		fi

		produced=true
	fi

	if "$done"; then
		echo "D"
		exit 0
	else
		echo "Y"
	fi
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
		#TODO: Check integer matches file length

		done=true
		;;

	*)
		error "unexpected key: $key"
		;;

	esac
}

function main() {
	file="${1:-}"

	if [[ "$file" == "" ]]; then
		printf "Usage:\n\t%s FILE\n" "$NAME" >&2
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
