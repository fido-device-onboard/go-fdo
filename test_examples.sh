#!/bin/bash
#
# FDO Example Application Test Script
# Runs through the examples from README.md and delegate.md
#
# Usage: ./test_examples.sh [test_name]
#   test_name: basic, rv-blob, kex, delegate, delegate-fdo200, all (default: all)
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DB_FILE="test.db"
SERVER_ADDR="127.0.0.1:9999"
SERVER_URL="http://${SERVER_ADDR}"
CRED_FILE="cred.bin"
SERVER_PID=""

# Cleanup function
cleanup() {
	echo -e "${YELLOW}Cleaning up...${NC}"
	if [ -n "$SERVER_PID" ]; then
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
	fi
	pkill -f "go-build.*server" 2>/dev/null || true
	rm -f "$DB_FILE" "$CRED_FILE" key.pem /tmp/fdo_server.log 2>/dev/null || true
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

	# Start server in background, redirecting output to a temp file
	# shellcheck disable=SC2086 # $flags intentionally unquoted for word splitting
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
	all)
		test_all
		;;
	*)
		echo "Unknown test: $test_name"
		echo "Available tests: basic, basic-reuse, rv-blob, kex, fdo200, delegate, delegate-fdo200, all"
		exit 1
		;;
	esac
}

main "$@"
