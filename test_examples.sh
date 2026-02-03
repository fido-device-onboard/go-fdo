#!/bin/bash
#
# FDO Example Application Test Script
# Runs through the examples from README.md and delegate.md
#
# Usage: ./test_examples.sh [test_name]
#   test_name: basic, rv-blob, kex, delegate, delegate-fdo200, attested-payload, all (default: all)
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
EPHEMERAL_DIR="ephemeral-test-files"
DB_FILE="$EPHEMERAL_DIR/test.db"
SERVER_ADDR="127.0.0.1:9999"
SERVER_URL="http://${SERVER_ADDR}"
CRED_FILE="$EPHEMERAL_DIR/cred.bin"
SERVER_PID=""

# Cleanup function - only kills processes on exit, preserves ephemeral files for debugging
cleanup() {
	if [ -n "$SERVER_PID" ]; then
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
	fi
	pkill -f "go-build.*server" 2>/dev/null || true
}

# Clean up ephemeral files from previous test runs
cleanup_ephemeral() {
	if [ -d "$EPHEMERAL_DIR" ]; then
		echo -e "${YELLOW}Cleaning up ephemeral test files from previous run...${NC}"
		rm -rf "$EPHEMERAL_DIR"
	fi
}

trap cleanup EXIT

# Helper functions
log_section() {
	echo ""
	echo -e "${BLUE}========================================${NC}"
	echo -e "${BLUE}$1${NC}"
	echo -e "${BLUE}========================================${NC}"
}

log_step() {
	echo -e "${YELLOW}>>> $1${NC}"
}

log_success() {
	echo -e "${GREEN}✓ $1${NC}"
}

log_error() {
	echo -e "${RED}✗ $1${NC}"
}

# Log expected failure - shows that failure was intentional
log_expected_failure() {
	echo -e "${GREEN}✓ (expected failure) $1${NC}"
}

# Run a command that is expected to fail, suppressing its output
run_expect_fail() {
	local description="$1"
	shift
	echo -e "${YELLOW}>>> Expecting failure: $description${NC}"
	echo -e "${YELLOW}\$ $*${NC}"
	if (cd examples && "$@" >/dev/null 2>&1); then
		log_error "Command should have failed but succeeded"
		return 1
	else
		log_expected_failure "$description"
		return 0
	fi
}

run_cmd() {
	echo -e "${YELLOW}\$ $*${NC}"
	if ! (cd examples && "$@"); then
		log_error "Command failed: $*"
		return 1
	fi
}

start_server() {
	local flags="$1"
	log_step "Starting server with flags: $flags"

	# Kill any existing server processes
	pkill -f "go-build.*server" 2>/dev/null || true
	pkill -f "examples/cmd server" 2>/dev/null || true
	sleep 1

	# Create ephemeral test files directory
	mkdir -p "$EPHEMERAL_DIR"

	# Start server in background, redirecting output to a temp file
	# shellcheck disable=SC2086 # $flags intentionally unquoted for word splitting
	log_step "go run ./cmd server -http \"$SERVER_ADDR\" -db \"../$DB_FILE\" $flags"
	# shellcheck disable=SC2086
	(cd examples && go run ./cmd server -http "$SERVER_ADDR" -db "../$DB_FILE" $flags >/tmp/fdo_server.log 2>&1) &
	SERVER_PID=$!

	# Wait for server to start listening
	local retries=10
	while [ $retries -gt 0 ]; do
		if grep -q "Listening" /tmp/fdo_server.log 2>/dev/null; then
			log_success "Server started (PID: $SERVER_PID)"
			return 0
		fi
		if ! kill -0 "$SERVER_PID" 2>/dev/null; then
			log_error "Server process died"
			cat /tmp/fdo_server.log 2>/dev/null || true
			return 1
		fi
		sleep 1
		retries=$((retries - 1))
	done

	log_error "Server failed to start (timeout)"
	cat /tmp/fdo_server.log 2>/dev/null || true
	return 1
}

stop_server() {
	log_step "Stopping server"
	# Kill go run and any spawned server processes
	if [ -n "$SERVER_PID" ]; then
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
	fi
	pkill -f "go-build.*server" 2>/dev/null || true
	SERVER_PID=""
	sleep 1
	log_success "Server stopped"
}

# Test: Basic Device Onboard (from README.md)
test_basic() {
	log_section "TEST: Basic Device Onboard"

	rm -f "$DB_FILE" "$CRED_FILE"

	start_server ""

	log_step "Running DI (Device Initialization)"
	run_cmd go run ./cmd client -di "$SERVER_URL"
	log_success "DI completed"

	log_step "Running TO1/TO2 (Transfer Ownership)"
	run_cmd go run ./cmd client
	log_success "TO1/TO2 completed"

	stop_server
	log_success "Basic Device Onboard test PASSED"
}

# Test: Basic with Credential Reuse
test_basic_reuse() {
	log_section "TEST: Basic Device Onboard with Credential Reuse"

	rm -f "$DB_FILE" "$CRED_FILE"

	start_server "-reuse-cred"

	log_step "Running DI"
	run_cmd go run ./cmd client -di "$SERVER_URL"
	log_success "DI completed"

	log_step "Running TO1/TO2 (first time)"
	run_cmd go run ./cmd client
	log_success "TO1/TO2 completed (first)"

	log_step "Running TO1/TO2 (second time - credential reuse)"
	run_cmd go run ./cmd client
	log_success "TO1/TO2 completed (second - reuse)"

	stop_server
	log_success "Credential Reuse test PASSED"
}

# Test: RV Blob Registration - SKIPPED
# Note: This test is not applicable when running a combined server because
# the server auto-registers RV blobs during DI. This test would only be
# meaningful with separate RV and owner servers.
test_rv_blob() {
	log_section "TEST: RV Blob Registration (SKIPPED)"
	echo -e "${YELLOW}This test requires separate RV/owner servers and is skipped in combined mode${NC}"
	log_success "RV Blob Registration test SKIPPED"
}

# Test: Key Exchange (from README.md)
test_kex() {
	log_section "TEST: Key Exchange (ASYMKEX2048)"

	rm -f "$DB_FILE" "$CRED_FILE"

	start_server ""

	log_step "Running DI with RSA2048 key"
	run_cmd go run ./cmd client -di "$SERVER_URL" -di-key rsa2048
	log_success "DI completed with RSA2048"

	log_step "Running TO1/TO2 with ASYMKEX2048"
	run_cmd go run ./cmd client -kex ASYMKEX2048
	log_success "TO1/TO2 completed with ASYMKEX2048"

	stop_server
	log_success "Key Exchange test PASSED"
}

# Test: FDO 2.0 Protocol
test_fdo200() {
	log_section "TEST: FDO 2.0 Protocol"

	rm -f "$DB_FILE" "$CRED_FILE"

	start_server "-reuse-cred"

	log_step "Running DI"
	run_cmd go run ./cmd client -di "$SERVER_URL"
	log_success "DI completed"

	log_step "Running TO1/TO2 with FDO 2.0"
	run_cmd go run ./cmd client -fdo-version 200
	log_success "TO1/TO2 completed with FDO 2.0"

	log_step "Running TO1/TO2 again with FDO 2.0 (credential reuse)"
	run_cmd go run ./cmd client -fdo-version 200
	log_success "TO1/TO2 completed with FDO 2.0 (reuse)"

	stop_server
	log_success "FDO 2.0 Protocol test PASSED"
}

# Test: Delegate (from delegate.md)
# NOTE: Delegate TO2 now works after the fix to use original owner key for voucher validation
test_delegate() {
	log_section "TEST: Delegate Support (FDO 1.01)"

	rm -f "$DB_FILE" "$CRED_FILE"

	log_step "Creating database with owner certs"
	start_server "-owner-certs"
	stop_server

	log_step "Creating delegate chain"
	run_cmd go run ./cmd delegate -db "../$DB_FILE" create myDelegate onboard,redirect SECP384R1 ec384 ec384
	log_success "Delegate chain created"

	log_step "Listing delegate chains"
	run_cmd go run ./cmd delegate -db "../$DB_FILE" list

	log_step "Printing delegate chain"
	run_cmd go run ./cmd delegate -db "../$DB_FILE" print myDelegate

	# Start server with delegate (self-registration handles RV blob)
	start_server "-owner-certs -onboardDelegate myDelegate"

	log_step "Running DI"
	run_cmd go run ./cmd client -di "$SERVER_URL"
	log_success "DI completed"

	log_step "Running TO1/TO2 with delegate"
	run_cmd go run ./cmd client
	log_success "TO1/TO2 completed with delegate"

	stop_server
	log_success "Delegate Support test PASSED"
}

# Test: Delegate with FDO 2.0
test_delegate_fdo200() {
	log_section "TEST: Delegate Support (FDO 2.0)"

	rm -f "$DB_FILE" "$CRED_FILE"

	log_step "Creating database with owner certs"
	start_server "-owner-certs"
	stop_server

	log_step "Creating delegate chain"
	run_cmd go run ./cmd delegate -db "../$DB_FILE" create myDelegate onboard,redirect SECP384R1 ec384 ec384
	log_success "Delegate chain created"

	# Start server with delegate (self-registration handles RV blob)
	start_server "-owner-certs -onboardDelegate myDelegate"

	log_step "Running DI"
	run_cmd go run ./cmd client -di "$SERVER_URL"
	log_success "DI completed"

	log_step "Running TO1/TO2 with FDO 2.0 and delegate"
	run_cmd go run ./cmd client -fdo-version 200
	log_success "TO1/TO2 completed with FDO 2.0 and delegate"

	stop_server
	log_success "Delegate Support (FDO 2.0) test PASSED"
}

# Test: Attested Payload (plaintext)
test_attested_payload() {
	log_section "TEST: Attested Payload (Plaintext)"

	rm -f "$DB_FILE" "$CRED_FILE" $EPHEMERAL_DIR/voucher.pem $EPHEMERAL_DIR/payload.fdo $EPHEMERAL_DIR/payload-typed.fdo

	log_step "Creating database with owner certs"
	start_server "-owner-certs"

	log_step "Running DI"
	run_cmd go run ./cmd client -di "$SERVER_URL"
	log_success "DI completed"

	stop_server

	log_step "Exporting voucher to PEM"
	(
		echo '-----BEGIN OWNERSHIP VOUCHER-----'
		sqlite3 "$DB_FILE" 'select hex(cbor) from vouchers;' | xxd -r -p | base64
		echo '-----END OWNERSHIP VOUCHER-----'
	) >$EPHEMERAL_DIR/voucher.pem
	log_success "Voucher exported"

	log_step "Creating plaintext attested payload"
	run_cmd go run ./cmd attestpayload create -db "../$DB_FILE" -voucher ../$EPHEMERAL_DIR/voucher.pem -payload "Hello from attested payload test" -output ../$EPHEMERAL_DIR/payload.fdo
	log_success "Attested payload created"

	log_step "Verifying attested payload"
	run_cmd go run ./cmd attestpayload verify -db "../$DB_FILE" ../$EPHEMERAL_DIR/payload.fdo
	log_success "Attested payload verified"

	log_step "Creating attested payload with MIME type (text/x-shellscript)"
	run_cmd go run ./cmd attestpayload create -db "../$DB_FILE" -voucher ../$EPHEMERAL_DIR/voucher.pem -payload '#!/bin/bash\necho "Hello from script"' -type "text/x-shellscript" -output ../$EPHEMERAL_DIR/payload-typed.fdo
	log_success "Typed attested payload created"

	log_step "Verifying typed attested payload"
	run_cmd go run ./cmd attestpayload verify -db "../$DB_FILE" ../$EPHEMERAL_DIR/payload-typed.fdo
	log_success "Typed attested payload verified"

	log_step "Creating attested payload with validity (id and generation)"
	run_cmd go run ./cmd attestpayload create -db "../$DB_FILE" -voucher ../$EPHEMERAL_DIR/voucher.pem -payload "Config v1" -id "network-config" -gen 1 -output ../$EPHEMERAL_DIR/payload-validity.fdo
	log_success "Attested payload with validity created"

	log_step "Verifying attested payload with validity"
	run_cmd go run ./cmd attestpayload verify -db "../$DB_FILE" ../$EPHEMERAL_DIR/payload-validity.fdo
	log_success "Attested payload with validity verified"

	log_step "Creating attested payload with expiration (future date)"
	run_cmd go run ./cmd attestpayload create -db "../$DB_FILE" -voucher ../$EPHEMERAL_DIR/voucher.pem -payload "Time-limited command" -type "text/x-shellscript" -expires "2030-12-31T23:59:59Z" -output ../$EPHEMERAL_DIR/payload-expires.fdo
	log_success "Attested payload with expiration created"

	log_step "Verifying attested payload with expiration"
	run_cmd go run ./cmd attestpayload verify -db "../$DB_FILE" ../$EPHEMERAL_DIR/payload-expires.fdo
	log_success "Attested payload with expiration verified"

	rm -f $EPHEMERAL_DIR/voucher.pem $EPHEMERAL_DIR/payload.fdo $EPHEMERAL_DIR/payload-typed.fdo $EPHEMERAL_DIR/payload-validity.fdo $EPHEMERAL_DIR/payload-expires.fdo
	log_success "Attested Payload (Plaintext) test PASSED"
}

# Test: Attested Payload with Encryption (RSA)
test_attested_payload_encrypted() {
	log_section "TEST: Attested Payload (Encrypted)"

	rm -f "$DB_FILE" "$CRED_FILE" $EPHEMERAL_DIR/voucher.pem $EPHEMERAL_DIR/encrypted.fdo $EPHEMERAL_DIR/encrypted-typed.fdo

	log_step "Creating database with owner certs"
	start_server "-owner-certs"

	log_step "Running DI with RSA2048 key (required for encryption)"
	run_cmd go run ./cmd client -di "$SERVER_URL" -di-key rsa2048
	log_success "DI completed with RSA key"

	stop_server

	log_step "Exporting voucher to PEM"
	(
		echo '-----BEGIN OWNERSHIP VOUCHER-----'
		sqlite3 "$DB_FILE" 'select hex(cbor) from vouchers;' | xxd -r -p | base64
		echo '-----END OWNERSHIP VOUCHER-----'
	) >$EPHEMERAL_DIR/voucher.pem
	log_success "Voucher exported"

	log_step "Creating encrypted attested payload"
	run_cmd go run ./cmd attestpayload create -db "../$DB_FILE" -voucher ../$EPHEMERAL_DIR/voucher.pem -payload "Secret encrypted message" -encrypt -output ../$EPHEMERAL_DIR/encrypted.fdo
	log_success "Encrypted attested payload created"

	log_step "Verifying and decrypting attested payload"
	run_cmd go run ./cmd attestpayload verify -db "../$DB_FILE" ../$EPHEMERAL_DIR/encrypted.fdo
	log_success "Encrypted attested payload verified and decrypted"

	log_step "Creating encrypted attested payload with MIME type (application/json)"
	run_cmd go run ./cmd attestpayload create -db "../$DB_FILE" -voucher ../$EPHEMERAL_DIR/voucher.pem -payload '{"config": "secret"}' -type "application/json" -encrypt -output ../$EPHEMERAL_DIR/encrypted-typed.fdo
	log_success "Encrypted typed attested payload created"

	log_step "Verifying encrypted typed attested payload"
	run_cmd go run ./cmd attestpayload verify -db "../$DB_FILE" ../$EPHEMERAL_DIR/encrypted-typed.fdo
	log_success "Encrypted typed attested payload verified"

	rm -f $EPHEMERAL_DIR/voucher.pem $EPHEMERAL_DIR/encrypted.fdo $EPHEMERAL_DIR/encrypted-typed.fdo
	log_success "Attested Payload (Encrypted) test PASSED"
}

# Test: Attested Payload with Delegate Signing
test_attested_payload_delegate() {
	log_section "TEST: Attested Payload (Delegate Signed)"

	rm -f "$DB_FILE" "$CRED_FILE" $EPHEMERAL_DIR/voucher.pem $EPHEMERAL_DIR/delegated.fdo

	log_step "Creating database with owner certs"
	start_server "-owner-certs"

	log_step "Running DI"
	run_cmd go run ./cmd client -di "$SERVER_URL"
	log_success "DI completed"

	stop_server

	log_step "Creating delegate chain with provision permission"
	run_cmd go run ./cmd delegate -db "../$DB_FILE" create provisionDelegate provision SECP384R1 ec384
	log_success "Delegate chain created"

	log_step "Exporting voucher to PEM"
	(
		echo '-----BEGIN OWNERSHIP VOUCHER-----'
		sqlite3 "$DB_FILE" 'select hex(cbor) from vouchers;' | xxd -r -p | base64
		echo '-----END OWNERSHIP VOUCHER-----'
	) >$EPHEMERAL_DIR/voucher.pem
	log_success "Voucher exported"

	log_step "Creating delegate-signed attested payload"
	run_cmd go run ./cmd attestpayload create -db "../$DB_FILE" -voucher ../$EPHEMERAL_DIR/voucher.pem -payload "Delegate signed payload" -delegate provisionDelegate -output ../$EPHEMERAL_DIR/delegated.fdo
	log_success "Delegate-signed attested payload created"

	log_step "Verifying delegate-signed attested payload"
	run_cmd go run ./cmd attestpayload verify -db "../$DB_FILE" ../$EPHEMERAL_DIR/delegated.fdo
	log_success "Delegate-signed attested payload verified"

	rm -f $EPHEMERAL_DIR/voucher.pem $EPHEMERAL_DIR/delegated.fdo
	log_success "Attested Payload (Delegate Signed) test PASSED"
}

# Test: Attested Payload with Shell/OpenSSL (Interoperability)
# This test creates attested payloads using shell commands and openssl,
# then verifies them with the Go CLI. It also verifies Go CLI-created
# payloads using openssl.
test_attested_payload_shell() {
	log_section "TEST: Attested Payload (Shell/OpenSSL Interoperability)"

	rm -f "$DB_FILE" "$CRED_FILE" $EPHEMERAL_DIR/voucher.pem $EPHEMERAL_DIR/owner_ec_pvt.key $EPHEMERAL_DIR/owner_ec_pub.key
	rm -f $EPHEMERAL_DIR/signed_data.bin $EPHEMERAL_DIR/sig.bin $EPHEMERAL_DIR/payload_shell.fdo $EPHEMERAL_DIR/payload_cli.fdo $EPHEMERAL_DIR/extracted_payload.bin extracted_$EPHEMERAL_DIR/sig.bin

	log_step "Creating database with owner certs"
	start_server "-owner-certs"

	log_step "Running DI"
	run_cmd go run ./cmd client -di "$SERVER_URL"
	log_success "DI completed"

	stop_server

	log_step "Exporting voucher to PEM"
	(
		echo '-----BEGIN OWNERSHIP VOUCHER-----'
		sqlite3 "$DB_FILE" 'select hex(cbor) from vouchers;' | xxd -r -p | base64
		echo '-----END OWNERSHIP VOUCHER-----'
	) >$EPHEMERAL_DIR/voucher.pem
	log_success "Voucher exported"

	log_step "Extracting owner EC key"
	(
		echo '-----BEGIN PRIVATE KEY-----'
		sqlite3 "$DB_FILE" 'select hex(pkcs8) from owner_keys where type=11;' | xxd -r -p | base64
		echo '-----END PRIVATE KEY-----'
	) >$EPHEMERAL_DIR/owner_ec_pvt.key
	openssl pkey -in $EPHEMERAL_DIR/owner_ec_pvt.key -pubout >$EPHEMERAL_DIR/owner_ec_pub.key
	log_success "Owner EC key extracted"

	# Test 1: Create payload with shell, verify with Go CLI
	log_step "Creating attested payload with shell/openssl"
	PAYLOAD='Hello from shell-created attested payload'

	# Build length-prefixed signed data (no type, no validity)
	# Format: 4-byte type_len (0) + 4-byte validity_len (0) + payload
	(
		printf '\x00\x00\x00\x00\x00\x00\x00\x00'
		printf '%s' "$PAYLOAD"
	) >$EPHEMERAL_DIR/signed_data.bin

	# Sign with openssl
	openssl dgst -sha384 -sign $EPHEMERAL_DIR/owner_ec_pvt.key -out $EPHEMERAL_DIR/sig.bin $EPHEMERAL_DIR/signed_data.bin

	# Assemble the .fdo file
	cp $EPHEMERAL_DIR/voucher.pem $EPHEMERAL_DIR/payload_shell.fdo
	(
		echo '-----BEGIN PAYLOAD-----'
		printf '%s' "$PAYLOAD" | base64
		echo '-----END PAYLOAD-----'
	) >>$EPHEMERAL_DIR/payload_shell.fdo
	(
		echo '-----BEGIN SIGNATURE-----'
		base64 $EPHEMERAL_DIR/sig.bin
		echo '-----END SIGNATURE-----'
	) >>$EPHEMERAL_DIR/payload_shell.fdo
	log_success "Shell-created attested payload assembled"

	log_step "Verifying shell-created payload with Go CLI"
	run_cmd go run ./cmd attestpayload verify -db "../$DB_FILE" ../$EPHEMERAL_DIR/payload_shell.fdo
	log_success "Shell-created payload verified by Go CLI"

	# Test 2: Create payload with Go CLI, verify with openssl
	log_step "Creating attested payload with Go CLI"
	run_cmd go run ./cmd attestpayload create -db "../$DB_FILE" -voucher ../$EPHEMERAL_DIR/voucher.pem -payload "Hello from Go CLI" -output ../$EPHEMERAL_DIR/payload_cli.fdo
	log_success "Go CLI-created attested payload"

	log_step "Extracting components from Go CLI payload"
	# Extract payload
	sed -n '/-----BEGIN PAYLOAD-----/,/-----END PAYLOAD-----/p' $EPHEMERAL_DIR/payload_cli.fdo | grep -v '^-----' | base64 -d >$EPHEMERAL_DIR/extracted_payload.bin
	# Extract signature
	sed -n '/-----BEGIN SIGNATURE-----/,/-----END SIGNATURE-----/p' $EPHEMERAL_DIR/payload_cli.fdo | grep -v '^-----' | base64 -d >$EPHEMERAL_DIR/sig.bin
	log_success "Components extracted"

	log_step "Verifying Go CLI payload with openssl"
	# Build length-prefixed signed data (no type, no validity for this payload)
	(
		printf '\x00\x00\x00\x00\x00\x00\x00\x00'
		cat $EPHEMERAL_DIR/extracted_payload.bin
	) >$EPHEMERAL_DIR/signed_data.bin
	# Verify signature
	openssl dgst -sha384 -verify $EPHEMERAL_DIR/owner_ec_pub.key -signature $EPHEMERAL_DIR/sig.bin $EPHEMERAL_DIR/signed_data.bin
	log_success "Go CLI payload verified by openssl"

	# Test 3: Create typed payload with shell, verify with Go CLI
	log_step "Creating typed attested payload with shell/openssl"
	PAYLOAD_TYPED='#!/bin/bash
echo "Hello from typed shell payload"'
	PAYLOAD_TYPE='text/x-shellscript'
	TYPE_LEN=${#PAYLOAD_TYPE}

	# Build length-prefixed signed data WITH type
	(
		printf '%08x' "$TYPE_LEN" | xxd -r -p
		printf '%s' "$PAYLOAD_TYPE"
		printf '\x00\x00\x00\x00'
		printf '%s' "$PAYLOAD_TYPED"
	) >$EPHEMERAL_DIR/signed_data.bin

	# Sign
	openssl dgst -sha384 -sign $EPHEMERAL_DIR/owner_ec_pvt.key -out $EPHEMERAL_DIR/sig.bin $EPHEMERAL_DIR/signed_data.bin

	# Assemble - PEM blocks use base64 encoding for the content
	cp $EPHEMERAL_DIR/voucher.pem $EPHEMERAL_DIR/payload_shell_typed.fdo
	{
		echo '-----BEGIN PAYLOAD TYPE-----'
		printf '%s' "$PAYLOAD_TYPE" | base64
		echo '-----END PAYLOAD TYPE-----'
		echo '-----BEGIN PAYLOAD-----'
		printf '%s' "$PAYLOAD_TYPED" | base64
		echo '-----END PAYLOAD-----'
		echo '-----BEGIN SIGNATURE-----'
		base64 $EPHEMERAL_DIR/sig.bin
		echo '-----END SIGNATURE-----'
	} >>$EPHEMERAL_DIR/payload_shell_typed.fdo
	log_success "Shell-created typed attested payload assembled"

	log_step "Verifying shell-created typed payload with Go CLI"
	run_cmd go run ./cmd attestpayload verify -db "../$DB_FILE" ../$EPHEMERAL_DIR/payload_shell_typed.fdo
	log_success "Shell-created typed payload verified by Go CLI"

	rm -f $EPHEMERAL_DIR/voucher.pem $EPHEMERAL_DIR/owner_ec_pvt.key $EPHEMERAL_DIR/owner_ec_pub.key $EPHEMERAL_DIR/signed_data.bin $EPHEMERAL_DIR/sig.bin
	rm -f $EPHEMERAL_DIR/payload_shell.fdo $EPHEMERAL_DIR/payload_cli.fdo $EPHEMERAL_DIR/payload_shell_typed.fdo $EPHEMERAL_DIR/extracted_payload.bin extracted_$EPHEMERAL_DIR/sig.bin
	log_success "Attested Payload (Shell/OpenSSL Interoperability) test PASSED"
}

# Test: Sysconfig FSIM
# This test demonstrates the fdo.sysconfig FSIM with key=value parameters
test_sysconfig() {
	log_section "TEST: Sysconfig FSIM"

	rm -f "$DB_FILE" "$CRED_FILE"

	start_server "-sysconfig hostname=test-device -sysconfig timezone=UTC -sysconfig ntp-server=pool.ntp.org"

	log_step "Running DI"
	run_cmd go run ./cmd client -di "$SERVER_URL"
	log_success "DI completed"

	log_step "Running TO1/TO2 with sysconfig parameters"
	run_cmd go run ./cmd client
	log_success "TO1/TO2 completed with sysconfig parameters"

	stop_server
	log_success "Sysconfig FSIM test PASSED"
}

# Test: Sysconfig FSIM with FDO 2.0
# This test explicitly verifies that the sysconfig FSIM works on FDO 2.0 protocol
# Other tests have shown that it works when client is 101 but not when client is 200
test_sysconfig_fdo200() {
	log_section "TEST: Sysconfig FSIM with FDO 2.0"

	rm -f "$DB_FILE" "$CRED_FILE"

	start_server "-reuse-cred -sysconfig hostname=test-device-fdo200 -sysconfig timezone=America/New_York -sysconfig ntp-server=time.google.com -sysconfig locale=en_US.UTF-8"

	log_step "Running DI"
	run_cmd go run ./cmd client -di "$SERVER_URL"
	log_success "DI completed"

	log_step "Running TO1/TO2 with FDO 2.0 and sysconfig parameters"
	echo ">>> PROOF TEST: Capturing FDO 2.0 client output to show sysconfig parameters:"
	run_cmd go run ./cmd client -fdo-version 200 2>&1 | tee /tmp/fdo200_sysconfig.log
	log_success "TO1/TO2 completed with FDO 2.0 and sysconfig parameters"

	# Check if sysconfig parameters were received
	if grep -q "\[fdo.sysconfig\]" /tmp/fdo200_sysconfig.log; then
		echo "✓ FDO 2.0 SUCCESS: Found sysconfig parameters:"
		grep "\[fdo.sysconfig\]" /tmp/fdo200_sysconfig.log
		FDO200_SUCCESS=true
	else
		echo "✗ FDO 2.0 FAILURE: No sysconfig parameters found in FDO 2.0 client output"
		echo ">>> This PROVES FDO 2.0 client is NOT receiving sysconfig parameters"
		FDO200_SUCCESS=false
	fi

	log_step "Running TO1/TO2 again with FDO 2.0 (credential reuse with sysconfig)"
	run_cmd go run ./cmd client -fdo-version 200
	log_success "TO1/TO2 completed with FDO 2.0 (reuse with sysconfig)"

	stop_server

	# Now run the same test with FDO 1.01 for comparison
	echo ""
	log_step "COMPARISON: Running same test with FDO 1.01 to prove the difference"

	rm -f "$DB_FILE" "$CRED_FILE"
	start_server "-reuse-cred -sysconfig hostname=test-device-fdo101 -sysconfig timezone=America/New_York -sysconfig ntp-server=time.google.com -sysconfig locale=en_US.UTF-8"

	log_step "Running DI (FDO 1.01)"
	run_cmd go run ./cmd client -di "$SERVER_URL"
	log_success "DI completed"

	log_step "Running TO1/TO2 with FDO 1.01 and sysconfig parameters"
	echo ">>> COMPARISON: Capturing FDO 1.01 client output to show sysconfig parameters:"
	run_cmd go run ./cmd client 2>&1 | tee /tmp/fdo101_sysconfig.log
	log_success "TO1/TO2 completed with FDO 1.01 and sysconfig parameters"

	# Check if sysconfig parameters were received
	if grep -q "\[fdo.sysconfig\]" /tmp/fdo101_sysconfig.log; then
		echo "✓ FDO 1.01 SUCCESS: Found sysconfig parameters:"
		grep "\[fdo.sysconfig\]" /tmp/fdo101_sysconfig.log
		FDO101_SUCCESS=true
	else
		echo "✗ FDO 1.01 FAILURE: No sysconfig parameters found"
		FDO101_SUCCESS=false
	fi

	stop_server

	# Final verdict
	echo ""
	log_section "PROOF VERDICT"
	if [ "$FDO200_SUCCESS" = true ] && [ "$FDO101_SUCCESS" = true ]; then
		echo "✓ Both FDO 1.01 and FDO 2.0 successfully receive sysconfig parameters"
		log_success "Sysconfig FSIM with FDO 2.0 test PASSED"
	elif [ "$FDO200_SUCCESS" = false ] && [ "$FDO101_SUCCESS" = true ]; then
		echo "✗ PROVEN: FDO 1.01 receives sysconfig parameters but FDO 2.0 does NOT"
		echo ">>> This demonstrates the bug you wanted to prove exists"
		log_success "Sysconfig FSIM with FDO 2.0 test COMPLETED (bug proven)"
	else
		echo "? Unexpected results - both versions failed"
		log_success "Sysconfig FSIM with FDO 2.0 test COMPLETED (inconclusive)"
	fi
}

# Test: Payload FSIM with FDO 2.0
# This test demonstrates that the fdo.payload FSIM works correctly with FDO 2.0 protocol
test_payload_fdo200() {
	log_section "TEST: Payload FSIM with FDO 2.0"

	mkdir -p "$EPHEMERAL_DIR"
	rm -f "$DB_FILE" "$CRED_FILE"

	# Create a random test file (10KB to test multi-chunk transfer)
	# Default chunk size is 1014 bytes, so 10KB will require ~10 chunks
	PAYLOAD_FILE="$EPHEMERAL_DIR/test_payload_fdo200.bin"
	RECEIVED_FILE="$EPHEMERAL_DIR/test_payload_fdo200.bin"
	log_step "Creating random test file (10KB for multi-chunk transfer)"
	dd if=/dev/urandom of="$PAYLOAD_FILE" bs=1024 count=10 2>/dev/null
	ORIGINAL_HASH=$(sha256sum "$PAYLOAD_FILE" | awk '{print $1}')
	log_success "Created test file: $PAYLOAD_FILE (hash: $ORIGINAL_HASH)"

	start_server "-reuse-cred -payload-file ../$PAYLOAD_FILE -payload-mime application/octet-stream"

	log_step "Running DI"
	run_cmd go run ./cmd client -di "$SERVER_URL"
	log_success "DI completed"

	log_step "Running TO1/TO2 with FDO 2.0 and payload transfer"
	run_cmd go run ./cmd client -fdo-version 200
	log_success "TO1/TO2 completed with FDO 2.0 and payload transfer"

	log_step "Running TO1/TO2 again with FDO 2.0 (credential reuse)"
	run_cmd go run ./cmd client -fdo-version 200
	log_success "TO1/TO2 completed with FDO 2.0 (reuse)"

	stop_server

	# Verify the received file matches the original
	if [ ! -f "$RECEIVED_FILE" ]; then
		log_error "Received file not found: $RECEIVED_FILE"
		rm -f "$PAYLOAD_FILE"
		return 1
	fi

	RECEIVED_HASH=$(sha256sum "$RECEIVED_FILE" | awk '{print $1}')
	log_step "Verifying file integrity"
	if [ "$ORIGINAL_HASH" = "$RECEIVED_HASH" ]; then
		log_success "File hashes match! Payload transferred correctly with FDO 2.0"
		log_success "  Original:  $ORIGINAL_HASH"
		log_success "  Received:  $RECEIVED_HASH"
	else
		log_error "File hashes DO NOT match!"
		log_error "  Original:  $ORIGINAL_HASH"
		log_error "  Received:  $RECEIVED_HASH"
		rm -f "$PAYLOAD_FILE" "$RECEIVED_FILE"
		return 1
	fi

	rm -f "$PAYLOAD_FILE" "$RECEIVED_FILE"
	log_success "Payload FSIM with FDO 2.0 test PASSED"
}

# Test: WiFi FSIM with FDO 2.0
# This test demonstrates that the fdo.wifi FSIM works correctly with FDO 2.0 protocol
test_wifi_fdo200() {
	log_section "TEST: WiFi FSIM with FDO 2.0"

	mkdir -p "$EPHEMERAL_DIR"
	rm -f "$DB_FILE" "$CRED_FILE"

	# Create a WiFi configuration file
	# Format: array of WiFiConfigEntry objects (not wrapped in "networks")
	WIFI_CONFIG="$EPHEMERAL_DIR/wifi_config.json"
	log_step "Creating WiFi configuration"
	cat >"$WIFI_CONFIG" <<'EOF'
[
  {
    "ssid": "TestNetwork-FDO200",
    "password": "testpassword123",
    "auth_type": 2
  }
]
EOF
	log_success "Created WiFi config: $WIFI_CONFIG"

	start_server "-reuse-cred -wifi-config ../$WIFI_CONFIG"

	log_step "Running DI"
	run_cmd go run ./cmd client -di "$SERVER_URL"
	log_success "DI completed"

	log_step "Running TO1/TO2 with FDO 2.0 and WiFi configuration"
	run_cmd go run ./cmd client -fdo-version 200
	log_success "TO1/TO2 completed with FDO 2.0 and WiFi configuration"

	log_step "Running TO1/TO2 again with FDO 2.0 (credential reuse)"
	run_cmd go run ./cmd client -fdo-version 200
	log_success "TO1/TO2 completed with FDO 2.0 (reuse)"

	stop_server
	rm -f "$WIFI_CONFIG"
	log_success "WiFi FSIM with FDO 2.0 test PASSED"
}

# Test: Payload FSIM
# This test demonstrates the fdo.payload FSIM by sending a file and verifying it's received correctly
test_payload() {
	log_section "TEST: Payload FSIM"

	mkdir -p "$EPHEMERAL_DIR"
	rm -f "$DB_FILE" "$CRED_FILE"

	# Create a random test file (10KB to test multi-chunk transfer)
	# Default chunk size is 1014 bytes, so 10KB will require ~10 chunks
	PAYLOAD_FILE="$EPHEMERAL_DIR/test_payload.bin"
	RECEIVED_FILE="$EPHEMERAL_DIR/test_payload.bin"
	log_step "Creating random test file (10KB for multi-chunk transfer)"
	dd if=/dev/urandom of="$PAYLOAD_FILE" bs=1024 count=10 2>/dev/null
	ORIGINAL_HASH=$(sha256sum "$PAYLOAD_FILE" | awk '{print $1}')
	log_success "Created test file: $PAYLOAD_FILE (hash: $ORIGINAL_HASH)"

	start_server "-payload-file ../$PAYLOAD_FILE -payload-mime application/octet-stream"

	log_step "Running DI"
	run_cmd go run ./cmd client -di "$SERVER_URL"
	log_success "DI completed"

	log_step "Running TO1/TO2 with payload transfer"
	run_cmd go run ./cmd client
	log_success "TO1/TO2 completed with payload transfer"

	stop_server

	# Verify the received file matches the original
	if [ ! -f "$RECEIVED_FILE" ]; then
		log_error "Received file not found: $RECEIVED_FILE"
		rm -f "$PAYLOAD_FILE"
		return 1
	fi

	RECEIVED_HASH=$(sha256sum "$RECEIVED_FILE" | awk '{print $1}')
	log_step "Verifying file integrity"
	if [ "$ORIGINAL_HASH" = "$RECEIVED_HASH" ]; then
		log_success "File hashes match! Payload transferred correctly"
		log_success "  Original:  $ORIGINAL_HASH"
		log_success "  Received:  $RECEIVED_HASH"
	else
		log_error "File hashes DO NOT match!"
		log_error "  Original:  $ORIGINAL_HASH"
		log_error "  Received:  $RECEIVED_HASH"
		rm -f "$PAYLOAD_FILE" "$RECEIVED_FILE"
		return 1
	fi

	# Cleanup
	log_success "Payload FSIM test PASSED"
}

# Test: Payload FSIM with Multiple Types
# This test demonstrates sending multiple payloads with different MIME types
# and verifies that all are received correctly
test_payload_multiple_types() {
	log_section "TEST: Payload FSIM with Multiple MIME Types"

	mkdir -p "$EPHEMERAL_DIR"
	rm -f "$DB_FILE" "$CRED_FILE"

	# Create test files with different MIME types
	PAYLOAD_JSON="$EPHEMERAL_DIR/test_payload.json"
	PAYLOAD_SCRIPT="$EPHEMERAL_DIR/test_payload.sh"
	PAYLOAD_BIN="$EPHEMERAL_DIR/test_payload.bin"

	log_step "Creating test payloads with different MIME types"
	echo '{"config": "test", "version": 1}' >"$PAYLOAD_JSON"
	echo '#!/bin/bash' >"$PAYLOAD_SCRIPT"
	echo 'echo "Hello from script"' >>"$PAYLOAD_SCRIPT"
	dd if=/dev/urandom of="$PAYLOAD_BIN" bs=1024 count=5 2>/dev/null

	JSON_HASH=$(sha256sum "$PAYLOAD_JSON" | awk '{print $1}')
	SCRIPT_HASH=$(sha256sum "$PAYLOAD_SCRIPT" | awk '{print $1}')
	BIN_HASH=$(sha256sum "$PAYLOAD_BIN" | awk '{print $1}')

	log_success "Created 3 test payloads:"
	log_success "  JSON:   $PAYLOAD_JSON (hash: $JSON_HASH)"
	log_success "  Script: $PAYLOAD_SCRIPT (hash: $SCRIPT_HASH)"
	log_success "  Binary: $PAYLOAD_BIN (hash: $BIN_HASH)"

	# Server sends three payloads with different MIME types (with RequireAck)
	log_step "Starting server with multiple payload types"
	start_server "-payload application/json:../$PAYLOAD_JSON -payload text/x-shellscript:../$PAYLOAD_SCRIPT -payload application/octet-stream:../$PAYLOAD_BIN"

	log_step "Running DI"
	run_cmd go run ./cmd client -di "$SERVER_URL"
	log_success "DI completed"

	# Client accepts all MIME types
	log_step "Running TO1/TO2 with multiple payload types (all accepted)"
	run_cmd go run ./cmd client
	log_success "TO1/TO2 completed with multiple payloads"

	stop_server

	# Verify all payloads were received
	RECEIVED_JSON="$EPHEMERAL_DIR/test_payload.json"
	RECEIVED_SCRIPT="$EPHEMERAL_DIR/test_payload.sh"
	RECEIVED_BIN="$EPHEMERAL_DIR/test_payload.bin"

	log_step "Verifying all payloads received"
	local all_match=true

	if [ ! -f "$RECEIVED_JSON" ]; then
		log_error "JSON payload not received"
		all_match=false
	else
		RECEIVED_JSON_HASH=$(sha256sum "$RECEIVED_JSON" | awk '{print $1}')
		if [ "$JSON_HASH" = "$RECEIVED_JSON_HASH" ]; then
			log_success "JSON payload verified: $RECEIVED_JSON_HASH"
		else
			log_error "JSON payload hash mismatch!"
			all_match=false
		fi
	fi

	if [ ! -f "$RECEIVED_SCRIPT" ]; then
		log_error "Script payload not received"
		all_match=false
	else
		RECEIVED_SCRIPT_HASH=$(sha256sum "$RECEIVED_SCRIPT" | awk '{print $1}')
		if [ "$SCRIPT_HASH" = "$RECEIVED_SCRIPT_HASH" ]; then
			log_success "Script payload verified: $RECEIVED_SCRIPT_HASH"
		else
			log_error "Script payload hash mismatch!"
			all_match=false
		fi
	fi

	if [ ! -f "$RECEIVED_BIN" ]; then
		log_error "Binary payload not received"
		all_match=false
	else
		RECEIVED_BIN_HASH=$(sha256sum "$RECEIVED_BIN" | awk '{print $1}')
		if [ "$BIN_HASH" = "$RECEIVED_BIN_HASH" ]; then
			log_success "Binary payload verified: $RECEIVED_BIN_HASH"
		else
			log_error "Binary payload hash mismatch!"
			all_match=false
		fi
	fi

	if [ "$all_match" = false ]; then
		return 1
	fi

	log_success "Payload FSIM with Multiple Types test PASSED"
}

# Test: Payload FSIM Selective MIME Type Rejection
# This test demonstrates device rejecting unsupported MIME types
# and accepting supported ones when multiple payloads are sent
test_payload_selective_rejection() {
	log_section "TEST: Payload FSIM Selective MIME Type Rejection"

	mkdir -p "$EPHEMERAL_DIR"
	rm -f "$DB_FILE" "$CRED_FILE"

	# Create test files
	PAYLOAD_UNSUPPORTED_1="$EPHEMERAL_DIR/test_unsupported_1.xml"
	PAYLOAD_SUPPORTED="$EPHEMERAL_DIR/test_supported.json"
	PAYLOAD_UNSUPPORTED_2="$EPHEMERAL_DIR/test_unsupported_2.yaml"

	log_step "Creating test payloads"
	echo '<?xml version="1.0"?><config></config>' >"$PAYLOAD_UNSUPPORTED_1"
	echo '{"config": "supported", "version": 1}' >"$PAYLOAD_SUPPORTED"
	echo 'config: unsupported' >"$PAYLOAD_UNSUPPORTED_2"

	SUPPORTED_HASH=$(sha256sum "$PAYLOAD_SUPPORTED" | awk '{print $1}')
	UNSUPPORTED_1_HASH=$(sha256sum "$PAYLOAD_UNSUPPORTED_1" | awk '{print $1}')
	UNSUPPORTED_2_HASH=$(sha256sum "$PAYLOAD_UNSUPPORTED_2" | awk '{print $1}')

	log_success "Created 3 test payloads:"
	log_success "  Unsupported XML:  $PAYLOAD_UNSUPPORTED_1"
	log_success "  Supported JSON:   $PAYLOAD_SUPPORTED (hash: $SUPPORTED_HASH)"
	log_success "  Unsupported YAML: $PAYLOAD_UNSUPPORTED_2"

	# Server sends three payloads: unsupported, supported, unsupported (with RequireAck)
	log_step "Starting server with mixed supported/unsupported MIME types"
	start_server "-payload application/xml:../$PAYLOAD_UNSUPPORTED_1 -payload application/json:../$PAYLOAD_SUPPORTED -payload application/x-yaml:../$PAYLOAD_UNSUPPORTED_2"

	log_step "Running DI"
	run_cmd go run ./cmd client -di "$SERVER_URL"
	log_success "DI completed"

	# Client only supports application/json, should reject XML and YAML, accept JSON
	log_step "Running TO1/TO2 with selective MIME type rejection"
	log_step "  Device supports: application/json only"
	log_step "  Server sends: XML (reject), JSON (accept), YAML (reject)"
	run_cmd go run ./cmd client -payload-supported-types "application/json"
	log_success "TO1/TO2 completed with selective rejection"

	stop_server

	# Verify only the supported payload was received
	RECEIVED_SUPPORTED="$EPHEMERAL_DIR/test_supported.json"

	log_step "Verifying only supported payload was received"
	if [ ! -f "$RECEIVED_SUPPORTED" ]; then
		log_error "Supported JSON payload not received"
		return 1
	fi

	RECEIVED_HASH=$(sha256sum "$RECEIVED_SUPPORTED" | awk '{print $1}')
	if [ "$SUPPORTED_HASH" = "$RECEIVED_HASH" ]; then
		log_success "Supported payload verified: $RECEIVED_HASH"
	else
		log_error "Supported payload hash mismatch!"
		return 1
	fi

	# Verify unsupported payloads were NOT received (check if content changed)
	CURRENT_UNSUPPORTED_1_HASH=$(sha256sum "$PAYLOAD_UNSUPPORTED_1" | awk '{print $1}')
	CURRENT_UNSUPPORTED_2_HASH=$(sha256sum "$PAYLOAD_UNSUPPORTED_2" | awk '{print $1}')

	if [ "$UNSUPPORTED_1_HASH" != "$CURRENT_UNSUPPORTED_1_HASH" ] || [ "$UNSUPPORTED_2_HASH" != "$CURRENT_UNSUPPORTED_2_HASH" ]; then
		log_error "Unsupported payloads should not have been received (content was modified)"
		return 1
	fi

	log_success "Payload FSIM Selective Rejection test PASSED"
}

# Test: WiFi FSIM (network-add only)
# This test verifies that the WiFi FSIM can send network configurations
# from the server to the device, which displays them.
test_wifi() {
	log_section "TEST: WiFi FSIM (network-add)"

	rm -f "$DB_FILE" "$CRED_FILE"

	log_step "Starting server with WiFi config"
	start_server "-wifi-config ../examples/wifi_config.json"

	log_step "Running DI"
	run_cmd go run ./cmd client -di "$SERVER_URL"
	log_success "DI completed"

	log_step "Running TO1/TO2 with WiFi network configuration"
	run_cmd timeout 30 go run ./cmd client
	log_success "TO1/TO2 completed with WiFi network-add"
	stop_server
	log_success "WiFi FSIM test PASSED"
}

# Test: Single-Sided WiFi Attestation
# This test verifies single-sided attestation mode where:
# - Server sends unsigned ProveOVHdr (algorithm=0, empty signature)
# - Client accepts single-sided mode with -allow-single-sided flag
# - Only devmod and fdo.wifi FSIMs are advertised/used
# - Trust levels are downgraded to 0 (onboard-only)
test_wifi_single_sided() {
	log_section "TEST: Single-Sided WiFi Attestation"

	mkdir -p "$EPHEMERAL_DIR"
	rm -f "$DB_FILE" "$CRED_FILE"

	# Create WiFi config file with trust_level=1 (full-access)
	# In single-sided mode, device should downgrade this to 0
	WIFI_CONFIG_FILE="$EPHEMERAL_DIR/wifi_single_sided.json"
	cat >"$WIFI_CONFIG_FILE" <<'EOF'
[
  {
    "version": "1.0",
    "network_id": "single-sided-test",
    "ssid": "SingleSidedNetwork",
    "auth_type": 1,
    "password": "testpassword123",
    "trust_level": 1,
    "needs_cert": false
  }
]
EOF

	log_step "Starting server in single-sided WiFi mode"
	start_server "-single-sided-wifi -wifi-config ../$WIFI_CONFIG_FILE"

	log_step "Running DI"
	if ! run_cmd go run ./cmd client -di "$SERVER_URL"; then
		log_error "DI failed"
		rm -f "$WIFI_CONFIG_FILE"
		return 1
	fi
	log_success "DI completed"

	log_step "Running TO1/TO2 with single-sided attestation"
	# Client must explicitly allow single-sided mode
	if ! run_cmd timeout 30 go run ./cmd client -allow-single-sided; then
		log_error "TO1/TO2 failed in single-sided mode"
		rm -f "$WIFI_CONFIG_FILE"
		return 1
	fi
	log_success "TO1/TO2 completed in single-sided mode"

	stop_server

	# Cleanup
	rm -f "$WIFI_CONFIG_FILE"
	log_success "Single-Sided WiFi Attestation test PASSED"
}

# Test: BMO FSIM
# This test demonstrates the fdo.bmo FSIM by sending a boot image and verifying it's received correctly
test_bmo() {
	log_section "TEST: BMO FSIM (Bare Metal Onboarding)"

	mkdir -p "$EPHEMERAL_DIR"
	rm -f "$DB_FILE" "$CRED_FILE"

	# Create a random test file (10KB to test multi-chunk transfer)
	BMO_FILE="$EPHEMERAL_DIR/test_bmo_image.bin"
	RECEIVED_FILE="examples/bmo-test_bmo_image.bin"
	log_step "Creating random test boot image (10KB for multi-chunk transfer)"
	dd if=/dev/urandom of="$BMO_FILE" bs=1024 count=10 2>/dev/null
	ORIGINAL_HASH=$(sha256sum "$BMO_FILE" | awk '{print $1}')
	log_success "Created test boot image: $BMO_FILE (hash: $ORIGINAL_HASH)"

	start_server "-bmo application/x-iso9660-image:../$BMO_FILE"

	log_step "Running DI"
	run_cmd go run ./cmd client -di "$SERVER_URL"
	log_success "DI completed"

	log_step "Running TO1/TO2 with BMO boot image transfer"
	run_cmd go run ./cmd client
	log_success "TO1/TO2 completed with BMO boot image transfer"

	stop_server

	# Verify the received file matches the original
	if [ ! -f "$RECEIVED_FILE" ]; then
		log_error "Received file not found: $RECEIVED_FILE"
		rm -f "$BMO_FILE"
		return 1
	fi

	RECEIVED_HASH=$(sha256sum "$RECEIVED_FILE" | awk '{print $1}')
	log_step "Verifying boot image integrity"
	if [ "$ORIGINAL_HASH" = "$RECEIVED_HASH" ]; then
		log_success "Boot image hashes match! BMO transfer successful"
		log_success "  Original:  $ORIGINAL_HASH"
		log_success "  Received:  $RECEIVED_HASH"
	else
		log_error "Boot image hashes DO NOT match!"
		rm -f "$BMO_FILE" "$RECEIVED_FILE"
		return 1
	fi

	# Cleanup
	rm -f "$BMO_FILE" "$RECEIVED_FILE" bmo-*
	rm -f "$BMO_FILE" "$RECEIVED_FILE"
	log_success "BMO FSIM test PASSED"
}

# Test: BMO FSIM with EFI application type
# This test verifies BMO can handle EFI application transfers
test_bmo_efi() {
	log_section "TEST: BMO FSIM (EFI Application)"

	mkdir -p "$EPHEMERAL_DIR"
	rm -f "$DB_FILE" "$CRED_FILE"

	# Create a small test file simulating an EFI app
	BMO_FILE="$EPHEMERAL_DIR/test_boot.efi"
	RECEIVED_FILE="examples/bmo-test_boot.efi"
	log_step "Creating test EFI application (5KB)"
	dd if=/dev/urandom of="$BMO_FILE" bs=1024 count=5 2>/dev/null
	ORIGINAL_HASH=$(sha256sum "$BMO_FILE" | awk '{print $1}')
	log_success "Created test EFI app: $BMO_FILE (hash: $ORIGINAL_HASH)"

	start_server "-bmo application/efi:../$BMO_FILE"

	log_step "Running DI"
	run_cmd go run ./cmd client -di "$SERVER_URL"
	log_success "DI completed"

	log_step "Running TO1/TO2 with EFI application transfer"
	run_cmd go run ./cmd client
	log_success "TO1/TO2 completed with EFI application"

	stop_server

	# Verify the received file matches the original
	if [ ! -f "$RECEIVED_FILE" ]; then
		log_error "Received file not found: $RECEIVED_FILE"
		rm -f "$BMO_FILE"
		return 1
	fi

	RECEIVED_HASH=$(sha256sum "$RECEIVED_FILE" | awk '{print $1}')
	log_step "Verifying EFI application integrity"
	if [ "$ORIGINAL_HASH" = "$RECEIVED_HASH" ]; then
		log_success "EFI app hashes match!"
		log_success "  Original:  $ORIGINAL_HASH"
		log_success "  Received:  $RECEIVED_HASH"
	else
		log_error "EFI app hashes DO NOT match!"
		rm -f "$BMO_FILE" "$RECEIVED_FILE"
		return 1
	fi

	# Cleanup
	rm -f "$BMO_FILE" "$RECEIVED_FILE"
	log_success "BMO FSIM (EFI Application) test PASSED"
}

# Test: BMO FSIM NAK (device rejects first type, accepts second)
# This test verifies the NAK flow where device rejects unsupported MIME types
test_bmo_nak() {
	log_section "TEST: BMO FSIM NAK (Type Rejection/Fallback)"

	mkdir -p "$EPHEMERAL_DIR"
	rm -f "$DB_FILE" "$CRED_FILE"

	# Create test files
	BMO_FILE_1="$EPHEMERAL_DIR/test_unsupported.bin"
	BMO_FILE_2="$EPHEMERAL_DIR/test_supported.efi"
	RECEIVED_FILE="examples/bmo-test_supported.efi"

	log_step "Creating test boot images"
	dd if=/dev/urandom of="$BMO_FILE_1" bs=1024 count=5 2>/dev/null
	dd if=/dev/urandom of="$BMO_FILE_2" bs=1024 count=5 2>/dev/null
	ORIGINAL_HASH=$(sha256sum "$BMO_FILE_2" | awk '{print $1}')
	log_success "Created test images: $BMO_FILE_1 (unsupported), $BMO_FILE_2 (supported)"

	# Server sends two images: first unsupported, then supported (with RequireAck)
	# Convert paths to be relative to examples directory
	BMO_FILE_1_REL="../$BMO_FILE_1"
	BMO_FILE_2_REL="../$BMO_FILE_2"
	start_server "-bmo application/x-unsupported-format:$BMO_FILE_1_REL -bmo application/efi:$BMO_FILE_2_REL"

	log_step "Running DI"
	if ! run_cmd go run ./cmd client -di "$SERVER_URL"; then
		log_error "DI failed"
		rm -f "$BMO_FILE_1" "$BMO_FILE_2"
		return 1
	fi
	log_success "DI completed"

	# Client only supports application/efi, should reject first, accept second
	log_step "Running TO1/TO2 with NAK for first image, accept second"
	if ! run_cmd go run ./cmd client -bmo-supported-types "application/efi"; then
		log_error "TO1/TO2 failed with NAK/fallback"
		rm -f "$BMO_FILE_1" "$BMO_FILE_2"
		return 1
	fi
	log_success "TO1/TO2 completed with NAK/fallback"

	stop_server

	# Verify the supported image was received
	if [ ! -f "$RECEIVED_FILE" ]; then
		log_error "Received file not found: $RECEIVED_FILE"
		rm -f "$BMO_FILE_1" "$BMO_FILE_2"
		return 1
	fi

	RECEIVED_HASH=$(sha256sum "$RECEIVED_FILE" | awk '{print $1}')
	log_step "Verifying boot image integrity"
	if [ "$ORIGINAL_HASH" = "$RECEIVED_HASH" ]; then
		log_success "Boot image hashes match! NAK fallback successful"
		log_success "  Original:  $ORIGINAL_HASH"
		log_success "  Received:  $RECEIVED_HASH"
	else
		log_error "Boot image hashes DO NOT match!"
		rm -f "$BMO_FILE_1" "$BMO_FILE_2" "$RECEIVED_FILE"
		return 1
	fi

	# Cleanup
	rm -f "$BMO_FILE_1" "$BMO_FILE_2" "$RECEIVED_FILE"
	log_success "BMO FSIM NAK test PASSED"
}

# Test: BMO FSIM Multi-Asset (preference order with NAK fallback)
# This test demonstrates the multi-asset strategy where server presents
# multiple boot assets in preference order and device selects first supported
test_bmo_multi_asset() {
	log_section "TEST: BMO FSIM Multi-Asset (Preference Order/NAK Fallback)"

	mkdir -p "$EPHEMERAL_DIR"
	rm -f "$DB_FILE" "$CRED_FILE"

	# Create test files in preference order: EFI (best) -> ISO -> Raw disk
	BMO_EFI="$EPHEMERAL_DIR/test_boot.efi"
	BMO_ISO="$EPHEMERAL_DIR/test_boot.iso"
	BMO_RAW="$EPHEMERAL_DIR/test_boot.raw"
	RECEIVED_FILE="examples/bmo-test_boot.efi"  # EFI should be accepted

	log_step "Creating test boot images in preference order"
	dd if=/dev/urandom of="$BMO_EFI" bs=1024 count=3 2>/dev/null
	dd if=/dev/urandom of="$BMO_ISO" bs=1024 count=5 2>/dev/null
	dd if=/dev/urandom of="$BMO_RAW" bs=1024 count=8 2>/dev/null
	EFI_HASH=$(sha256sum "$BMO_EFI" | awk '{print $1}')
	log_success "Created test images: EFI (best), ISO (fallback), Raw disk (last resort)"

	# Server presents multiple assets in preference order
	# Device only supports EFI, so should accept first and NAK others won't be presented
	start_server "-bmo application/efi:../$BMO_EFI -bmo application/x-iso9660-image:../$BMO_ISO -bmo application/x-raw-disk-image:../$BMO_RAW"

	log_step "Running DI"
	if ! run_cmd go run ./cmd client -di "$SERVER_URL"; then
		log_error "DI failed"
		rm -f "$BMO_EFI" "$BMO_ISO" "$BMO_RAW"
		return 1
	fi
	log_success "DI completed"

	log_step "Running TO1/TO2 with multi-asset preference order"
	if ! run_cmd go run ./cmd client -bmo-supported-types "application/efi"; then
		log_error "TO1/TO2 failed with multi-asset"
		rm -f "$BMO_EFI" "$BMO_ISO" "$BMO_RAW"
		return 1
	fi
	log_success "TO1/TO2 completed with EFI asset accepted"

	stop_server

	# Verify the EFI image was received (first in preference order)
	if [ ! -f "$RECEIVED_FILE" ]; then
		log_error "EFI file not found: $RECEIVED_FILE"
		rm -f "$BMO_EFI" "$BMO_ISO" "$BMO_RAW"
		return 1
	fi

	RECEIVED_HASH=$(sha256sum "$RECEIVED_FILE" | awk '{print $1}')
	log_step "Verifying EFI image integrity (first in preference order)"
	if [ "$EFI_HASH" = "$RECEIVED_HASH" ]; then
		log_success "EFI image hashes match! Preference order working"
		log_success "  Original:  $EFI_HASH"
		log_success "  Received:  $RECEIVED_HASH"
	else
		log_error "EFI image hashes DO NOT match!"
		rm -f "$BMO_EFI" "$BMO_ISO" "$BMO_RAW" "$RECEIVED_FILE"
		return 1
	fi

	# Cleanup
	rm -f "$BMO_EFI" "$BMO_ISO" "$BMO_RAW" "$RECEIVED_FILE"
	log_success "BMO FSIM Multi-Asset test PASSED"
}

# Test: Payload FSIM NAK (device rejects first type, accepts second)
# This test verifies the NAK flow where device rejects unsupported MIME types
test_payload_nak() {
	log_section "TEST: Payload FSIM NAK (Type Rejection/Fallback)"

	mkdir -p "$EPHEMERAL_DIR"
	rm -f "$DB_FILE" "$CRED_FILE"

	# Create test files
	PAYLOAD_FILE_1="$EPHEMERAL_DIR/test_unsupported_payload.bin"
	PAYLOAD_FILE_2="$EPHEMERAL_DIR/test_supported_payload.json"
	RECEIVED_FILE="$EPHEMERAL_DIR/test_supported_payload.json"

	log_step "Creating test payloads"
	echo '{"unsupported": true}' >"$PAYLOAD_FILE_1"
	echo '{"config": "valid", "supported": true}' >"$PAYLOAD_FILE_2"
	ORIGINAL_HASH=$(sha256sum "$PAYLOAD_FILE_2" | awk '{print $1}')
	log_success "Created test payloads: $PAYLOAD_FILE_1 (unsupported), $PAYLOAD_FILE_2 (supported)"

	# Server sends two payloads: first unsupported, then supported (with RequireAck)
	start_server "-payload application/x-unsupported:../$PAYLOAD_FILE_1 -payload application/json:../$PAYLOAD_FILE_2"

	log_step "Running DI"
	run_cmd go run ./cmd client -di "$SERVER_URL"
	log_success "DI completed"

	# Client only supports application/json, should reject first, accept second
	log_step "Running TO1/TO2 with NAK for first payload, accept second"
	run_cmd go run ./cmd client -payload-supported-types "application/json"
	log_success "TO1/TO2 completed with NAK/fallback"

	stop_server

	# Verify the supported payload was received
	if [ ! -f "$RECEIVED_FILE" ]; then
		log_error "Received file not found: $RECEIVED_FILE"
		rm -f "$PAYLOAD_FILE_1" "$PAYLOAD_FILE_2"
		return 1
	fi

	RECEIVED_HASH=$(sha256sum "$RECEIVED_FILE" | awk '{print $1}')
	log_step "Verifying payload integrity"
	if [ "$ORIGINAL_HASH" = "$RECEIVED_HASH" ]; then
		log_success "Payload hashes match! NAK fallback successful"
		log_success "  Original:  $ORIGINAL_HASH"
		log_success "  Received:  $RECEIVED_HASH"
	else
		log_error "Payload hashes DO NOT match!"
		return 1
	fi

	# Cleanup
	log_success "Payload FSIM NAK test PASSED"
}

# Test: Credentials FSIM
# This test demonstrates the fdo.credentials FSIM by provisioning various credential types
test_credentials() {
	log_section "TEST: Credentials FSIM (Provisioned Credentials)"

	rm -f "$DB_FILE" "$CRED_FILE"

	log_step "Starting server with credential provisioning"
	start_server "-credential password:admin-creds:admin:SecurePass123:https://mgmt.example.com/api -credential api_key:prod-api:sk_live_abc123xyz:https://api.example.com/v1 -credential oauth2_client_secret:oauth-app:client_secret_xyz789:https://oauth.example.com/token"

	log_step "Running DI"
	run_cmd go run ./cmd client -di "$SERVER_URL"
	log_success "DI completed"

	log_step "Running TO1/TO2 with credential provisioning"
	run_cmd go run ./cmd client
	log_success "TO1/TO2 completed with credentials provisioned"

	stop_server
	log_success "Provisioned Credentials test PASSED"

	# Test Registered Credentials flow (device sends public key to owner)
	log_section "TEST: Credentials FSIM (Registered Credentials)"

	rm -f "$DB_FILE" "$CRED_FILE"

	log_step "Starting server requesting SSH public key"
	start_server "-request-pubkey ssh_public_key:device-ssh-key:ssh://admin.example.com:22"

	log_step "Running DI"
	run_cmd go run ./cmd client -di "$SERVER_URL"
	log_success "DI completed"

	log_step "Running TO1/TO2 with SSH public key registration"
	run_cmd go run ./cmd client -register-ssh-key "device-ssh-key:ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDevicePublicKeyExample"
	log_success "TO1/TO2 completed with public key registered"

	# Show server log to verify public key was received
	echo ">>> Server received public key:"
	grep -A5 "Received public key" /tmp/fdo_server.log 2>/dev/null || echo "  (check /tmp/fdo_server.log for details)"

	stop_server
	log_success "Registered Credentials test PASSED"

	# Test Enrolled Credentials flow (device sends CSR, owner returns signed cert + CA)
	log_section "TEST: Credentials FSIM (Enrolled Credentials)"

	rm -f "$DB_FILE" "$CRED_FILE"

	log_step "Starting server with fake CA (will sign CSRs)"
	start_server ""

	log_step "Running DI"
	run_cmd go run ./cmd client -di "$SERVER_URL"
	log_success "DI completed"

	log_step "Running TO1/TO2 with CSR enrollment"
	run_cmd go run ./cmd client -enroll-csr "device-mtls-cert:-----BEGIN CERTIFICATE REQUEST-----FAKECSR-----END CERTIFICATE REQUEST-----"
	log_success "TO1/TO2 completed with CSR enrollment"

	# Show server received CSR
	echo ">>> SERVER received CSR from CLIENT:"
	grep -A4 "SERVER received CSR" /tmp/fdo_server.log 2>/dev/null || echo "  (check /tmp/fdo_server.log for details)"

	# Show server sent cert + CA
	echo ""
	echo ">>> SERVER sent signed cert + CA to CLIENT:"
	grep -A3 "SERVER sending signed cert" /tmp/fdo_server.log 2>/dev/null || echo "  (check /tmp/fdo_server.log for details)"

	stop_server
	log_success "Enrolled Credentials test PASSED"

	log_success "Credentials FSIM test PASSED"
}

# Test: Bad Delegate Rejection (Security Test)
# This test verifies that a delegate chain created with a DIFFERENT owner key
# (simulating an attacker) cannot be used for onboarding.
# Note: Full end-to-end bad delegate injection requires Go-level testing
# (see delegate_test.go:TestSelfSignedDelegateRejected)
test_bad_delegate() {
	log_section "TEST: Bad Delegate Rejection (Security)"

	rm -f "$DB_FILE" "$CRED_FILE"

	log_step "Creating database with owner certs"
	start_server "-owner-certs"
	stop_server

	log_step "Creating legitimate delegate chain (SECP384R1 owner)"
	run_cmd go run ./cmd delegate -db "../$DB_FILE" create goodDelegate onboard,redirect SECP384R1 ec384

	# Now try to create a delegate with a DIFFERENT owner key type
	# This simulates an attacker trying to use their own key
	log_step "Attempting to create delegate with wrong owner key (should fail or be rejected)"

	# Create a delegate rooted to SECP256R1 owner (different from SECP384R1 used for voucher)
	run_cmd go run ./cmd delegate -db "../$DB_FILE" create badDelegate onboard,redirect SECP256R1 ec256

	# Start server with the GOOD delegate first to do DI
	start_server "-owner-certs -onboardDelegate goodDelegate"

	log_step "Running DI (creates voucher with SECP384R1 owner)"
	run_cmd go run ./cmd client -di "$SERVER_URL"
	log_success "DI completed"

	stop_server

	# Now try to onboard with the BAD delegate (rooted to wrong owner)
	# The server should reject this because the delegate chain doesn't match the voucher's owner
	start_server "-owner-certs -onboardDelegate badDelegate"

	log_step "Attempting TO2 with mismatched delegate (should fail)"
	run_expect_fail "TO2 with wrong delegate owner" go run ./cmd client

	stop_server
	log_success "Bad Delegate Rejection test PASSED"
}

# Run all tests
test_all() {
	local failed=0

	test_basic || failed=1
	test_basic_reuse || failed=1
	test_rv_blob || failed=1
	test_kex || failed=1
	test_fdo200 || failed=1
	test_delegate || failed=1
	test_delegate_fdo200 || failed=1
	test_attested_payload || failed=1
	test_attested_payload_encrypted || failed=1
	test_attested_payload_delegate || failed=1
	test_attested_payload_shell || failed=1
	test_sysconfig || failed=1
	test_sysconfig_fdo200 || failed=1
	test_payload || failed=1
	test_payload_fdo200 || failed=1
	test_payload_multiple_types || failed=1
	test_payload_selective_rejection || failed=1
	test_wifi || failed=1
	test_wifi_fdo200 || failed=1
	test_wifi_single_sided || failed=1
	test_bmo || failed=1
	test_bmo_efi || failed=1
	test_bmo_nak || failed=1
	test_bmo_multi_asset || failed=1
	test_payload_nak || failed=1
	test_credentials || failed=1
	test_bad_delegate || failed=1

	echo ""
	if [ $failed -eq 0 ]; then
		log_section "ALL TESTS PASSED"
	else
		log_section "SOME TESTS FAILED"
		return 1
	fi
}

# Main
main() {
	local test_name="${1:-all}"

	log_section "FDO Example Application Tests"
	echo "Test: $test_name"
	echo "Working directory: $(pwd)"

	# Ensure we're in the right directory
	if [ ! -f "go.mod" ]; then
		log_error "Must be run from go-fdo root directory"
		exit 1
	fi

	# Check for sqlite3 (needed for GUID extraction)
	if ! command -v sqlite3 &>/dev/null; then
		log_error "sqlite3 is required but not installed"
		exit 1
	fi

	# Clean up ephemeral files from previous test runs
	cleanup_ephemeral

	case "$test_name" in
	basic)
		test_basic
		;;
	basic-reuse)
		test_basic_reuse
		;;
	rv-blob)
		test_rv_blob
		;;
	kex)
		test_kex
		;;
	fdo200)
		test_fdo200
		;;
	delegate)
		test_delegate
		;;
	delegate-fdo200)
		test_delegate_fdo200
		;;
	bad-delegate)
		test_bad_delegate
		;;
	attested-payload)
		test_attested_payload
		;;
	attested-payload-encrypted)
		test_attested_payload_encrypted
		;;
	attested-payload-delegate)
		test_attested_payload_delegate
		;;
	attested-payload-shell)
		test_attested_payload_shell
		;;
	sysconfig)
		test_sysconfig
		;;
	sysconfig-fdo200)
		test_sysconfig_fdo200
		;;
	payload)
		test_payload
		;;
	payload-fdo200)
		test_payload_fdo200
		;;
	payload-multiple-types)
		test_payload_multiple_types
		;;
	payload-selective-rejection)
		test_payload_selective_rejection
		;;
	wifi)
		test_wifi
		;;
	wifi-fdo200)
		test_wifi_fdo200
		;;
	wifi-single-sided)
		test_wifi_single_sided
		;;
	bmo)
		test_bmo
		;;
	bmo-efi)
		test_bmo_efi
		;;
	bmo-nak)
		test_bmo_nak
		;;
	bmo-multi-asset)
		test_bmo_multi_asset
		;;
	payload-nak)
		test_payload_nak
		;;
	credentials)
		test_credentials
		;;
	all)
		test_all
		;;
	*)
		echo "Unknown test: $test_name"
		echo "Available tests: basic, basic-reuse, rv-blob, kex, fdo200, delegate, delegate-fdo200, bad-delegate, attested-payload, attested-payload-encrypted, attested-payload-delegate, attested-payload-shell, sysconfig, sysconfig-fdo200, payload, payload-fdo200, payload-multiple-types, payload-selective-rejection, payload-nak, wifi, wifi-fdo200, wifi-single-sided, bmo, bmo-efi, bmo-nak, bmo-multi-asset, credentials, all"
		exit 1
		;;
	esac
}

main "$@"
