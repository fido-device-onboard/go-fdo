#!/bin/bash
#
# FDO Example Application Test Script
# Runs through the examples from README.md and delegate.md
#
# Usage: ./test_examples.sh [test_name]
#   test_name: basic, basic-reuse, rv-blob, kex, fdo200, fdo200-di200, kex-fdo200, delegate, delegate-fdo200,
#              delegate-csr, bad-delegate, rv-verify-to1d, all (default: all)
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
	# Kill any remaining server processes more aggressively
	pkill -f "go-build.*server" 2>/dev/null || true
	pkill -f "examples/cmd server" 2>/dev/null || true
	pkill -f "cmd server" 2>/dev/null || true

	# Force kill if still running after 2 seconds
	sleep 2
	pkill -9 -f "go-build.*server" 2>/dev/null || true
	pkill -9 -f "examples/cmd server" 2>/dev/null || true
	pkill -9 -f "cmd server" 2>/dev/null || true
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

	# Kill any existing server processes and wait for port to be released
	pkill -f "go-build.*server" 2>/dev/null || true
	pkill -f "examples/cmd server" 2>/dev/null || true
	sleep 2

	# Wait for port to be released
	local retries=5
	while [ $retries -gt 0 ]; do
		if ! lsof -i :9999 >/dev/null 2>&1 && ! netstat -tulpn 2>/dev/null | grep :9999 >/dev/null; then
			break
		fi
		sleep 1
		retries=$((retries - 1))
	done

	# Create ephemeral test files directory
	mkdir -p "$EPHEMERAL_DIR"

	# Start server in background, redirecting output to a temp file
	# shellcheck disable=SC2086 # $flags intentionally unquoted for word splitting
	log_step "go run ./cmd server -http \"$SERVER_ADDR\" -db \"../$DB_FILE\" $flags"
	# shellcheck disable=SC2086
	(cd examples && go run ./cmd server -http "$SERVER_ADDR" -db "../$DB_FILE" $flags >../$EPHEMERAL_DIR/fdo_server.log 2>&1) &
	SERVER_PID=$!

	# Wait for server to start listening AND verify it's actually accepting connections
	local retries=15
	while [ $retries -gt 0 ]; do
		if grep -q "Listening" $EPHEMERAL_DIR/fdo_server.log 2>/dev/null; then
			# Log says listening - now verify the port is actually open
			sleep 0.5
			if nc -z 127.0.0.1 9999 2>/dev/null || (echo >/dev/tcp/127.0.0.1/9999) 2>/dev/null; then
				log_success "Server started (PID: $SERVER_PID)"
				return 0
			fi
			# Port not open yet, check if process died
			if ! kill -0 "$SERVER_PID" 2>/dev/null; then
				log_error "Server process died after logging Listening"
				cat $EPHEMERAL_DIR/fdo_server.log 2>/dev/null || true
				return 1
			fi
		fi
		if ! kill -0 "$SERVER_PID" 2>/dev/null; then
			log_error "Server process died"
			cat $EPHEMERAL_DIR/fdo_server.log 2>/dev/null || true
			return 1
		fi
		sleep 1
		retries=$((retries - 1))
	done

	log_error "Server failed to start (timeout)"
	cat $EPHEMERAL_DIR/fdo_server.log 2>/dev/null || true
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
	pkill -f "examples/cmd server" 2>/dev/null || true
	SERVER_PID=""

	# Wait for port to be released
	local retries=5
	while [ $retries -gt 0 ]; do
		if ! lsof -i :9999 >/dev/null 2>&1 && ! netstat -tulpn 2>/dev/null | grep :9999 >/dev/null; then
			break
		fi
		sleep 1
		retries=$((retries - 1))
	done

	sleep 1
	log_success "Server stopped"
}

# Test: Basic Device Onboard (from README.md)
test_basic() {
	log_section "TEST: Basic Device Onboard"

	rm -f "$DB_FILE" "$CRED_FILE"

	start_server ""

	log_step "Running DI (Device Initialization)"
	run_cmd go run ./cmd client -di "$SERVER_URL" || return 1
	log_success "DI completed"

	log_step "Running TO1/TO2 (Transfer Ownership)"
	run_cmd go run ./cmd client || return 1
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
	run_cmd go run ./cmd client -di "$SERVER_URL" || return 1
	log_success "DI completed"

	log_step "Running TO1/TO2 (first time)"
	run_cmd go run ./cmd client || return 1
	log_success "TO1/TO2 completed (first)"

	log_step "Running TO1/TO2 (second time - credential reuse)"
	run_cmd go run ./cmd client || return 1
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
	run_cmd go run ./cmd client -di "$SERVER_URL" -di-key rsa2048 || return 1
	log_success "DI completed with RSA2048"

	log_step "Running TO1/TO2 with ASYMKEX2048"
	run_cmd go run ./cmd client -kex ASYMKEX2048 || return 1
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
	run_cmd go run ./cmd client -di "$SERVER_URL" || return 1
	log_success "DI completed"

	log_step "Running TO1/TO2 with FDO 2.0"
	run_cmd go run ./cmd client -fdo-version 200 || return 1
	log_success "TO1/TO2 completed with FDO 2.0"

	log_step "Running TO1/TO2 again with FDO 2.0 (credential reuse)"
	run_cmd go run ./cmd client -fdo-version 200 || return 1
	log_success "TO1/TO2 completed with FDO 2.0 (reuse)"

	stop_server
	log_success "FDO 2.0 Protocol test PASSED"
}

# Test: FDO 2.0 key exchange negotiation. The Owner offers only the suites the
# spec allows for the attestation keys (RSA2048 owner: DHKEXid14; ASYMKEX is
# never offered in 2.0), and the Device must pick from that offer.
test_kex_fdo200() {
	log_section "TEST: FDO 2.0 Key Exchange Negotiation"

	rm -f "$DB_FILE" "$CRED_FILE"

	start_server "-reuse-cred"

	log_step "Running DI with RSA2048 key"
	run_cmd go run ./cmd client -di "$SERVER_URL" -di-key rsa2048 || return 1
	log_success "DI completed with RSA2048"

	log_step "Running TO1/TO2 at FDO 2.0, configured for ASYMKEX2048 (not offered in 2.0)"
	local out
	if ! out=$(cd examples && go run ./cmd client -fdo-version 200 -kex ASYMKEX2048 2>&1); then
		echo "$out"
		log_error "TO2 at FDO 2.0 failed"
		return 1
	fi
	if ! grep -q "DHKEXid14" <<<"$out"; then
		echo "$out"
		log_error "client did not fall back to the offered DHKEXid14"
		return 1
	fi
	log_success "Device used the Owner's offer: $(grep -o 'selected[^ ]*' <<<"$out" | head -1) $(grep -o 'DHKEXid14' <<<"$out" | head -1)"

	stop_server
	log_success "FDO 2.0 Key Exchange Negotiation test PASSED"
}

# Test: FDO 2.0 end-to-end, including DI at 2.0 (2.0 AppStart with capability flags)
test_fdo200_di200() {
	log_section "TEST: FDO 2.0 Protocol (DI at 2.0)"

	rm -f "$DB_FILE" "$CRED_FILE"

	start_server "-reuse-cred"

	log_step "Running DI with FDO 2.0"
	run_cmd go run ./cmd client -di "$SERVER_URL" -fdo-version 200 || return 1
	log_success "DI completed with FDO 2.0"

	log_step "Running TO1/TO2 with FDO 2.0"
	run_cmd go run ./cmd client -fdo-version 200 || return 1
	log_success "TO1/TO2 completed with FDO 2.0"

	stop_server
	log_success "FDO 2.0 Protocol (DI at 2.0) test PASSED"
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
	run_cmd go run ./cmd delegate -db "../$DB_FILE" create myDelegate onboard,redirect SECP384R1 ec384 ec384 || return 1
	log_success "Delegate chain created"

	log_step "Listing delegate chains"
	run_cmd go run ./cmd delegate -db "../$DB_FILE" list || return 1

	log_step "Printing delegate chain"
	run_cmd go run ./cmd delegate -db "../$DB_FILE" print myDelegate || return 1

	# Start server with delegate (self-registration handles RV blob)
	start_server "-owner-certs -onboardDelegate myDelegate"

	log_step "Running DI"
	run_cmd go run ./cmd client -di "$SERVER_URL" || return 1
	log_success "DI completed"

	log_step "Running TO1/TO2 with delegate"
	run_cmd go run ./cmd client || return 1
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
	run_cmd go run ./cmd delegate -db "../$DB_FILE" create myDelegate onboard,redirect SECP384R1 ec384 ec384 || return 1
	log_success "Delegate chain created"

	# Start server with delegate (self-registration handles RV blob)
	start_server "-owner-certs -onboardDelegate myDelegate"

	log_step "Running DI"
	run_cmd go run ./cmd client -di "$SERVER_URL" || return 1
	log_success "DI completed"

	log_step "Running TO1/TO2 with FDO 2.0 and delegate"
	run_cmd go run ./cmd client -fdo-version 200 || return 1
	log_success "TO1/TO2 completed with FDO 2.0 and delegate"

	stop_server
	log_success "Delegate Support (FDO 2.0) test PASSED"
}

# Test: Delegate CSR Workflow (generate-csr, sign-csr, import-cert)
test_delegate_csr() {
	log_section "TEST: Delegate CSR Workflow"

	rm -f "$DB_FILE" "$CRED_FILE"
	rm -f $EPHEMERAL_DIR/delegate-csr.*

	log_step "Creating database with owner certs"
	start_server "-owner-certs"
	stop_server

	# Note: run_cmd does "cd examples" so file paths need "../" prefix for EPHEMERAL_DIR
	log_step "Generating CSR (requester side, no DB needed)"
	run_cmd go run ./cmd delegate generate-csr testService ec384 -key-out "../$EPHEMERAL_DIR/delegate-csr.key.pem" >"$EPHEMERAL_DIR/delegate-csr.csr.pem" || return 1
	log_success "CSR generated"

	# Verify CSR file exists and is non-empty
	if [ ! -s "$EPHEMERAL_DIR/delegate-csr.csr.pem" ]; then
		log_error "CSR file is empty or missing"
		exit 1
	fi
	if [ ! -s "$EPHEMERAL_DIR/delegate-csr.key.pem" ]; then
		log_error "Private key file is empty or missing"
		exit 1
	fi
	log_success "CSR and key files verified"

	log_step "Signing CSR with redirect permission (owner side)"
	run_cmd go run ./cmd delegate -db "../$DB_FILE" sign-csr "../$EPHEMERAL_DIR/delegate-csr.csr.pem" csrDelegate redirect SECP384R1 >"$EPHEMERAL_DIR/delegate-csr.cert.pem" || return 1
	log_success "CSR signed"

	# Verify signed cert file exists and is non-empty
	if [ ! -s "$EPHEMERAL_DIR/delegate-csr.cert.pem" ]; then
		log_error "Signed cert file is empty or missing"
		exit 1
	fi
	log_success "Signed cert file verified"

	log_step "Importing signed cert + private key (requester side)"
	run_cmd go run ./cmd delegate -db "../$DB_FILE" import-cert importedDelegate "../$EPHEMERAL_DIR/delegate-csr.cert.pem" "../$EPHEMERAL_DIR/delegate-csr.key.pem" || return 1
	log_success "Cert imported"

	log_step "Listing delegate chains (should show both csrDelegate and importedDelegate)"
	run_cmd go run ./cmd delegate -db "../$DB_FILE" list || return 1
	log_success "Delegate chains listed"

	log_step "Printing imported delegate chain"
	run_cmd go run ./cmd delegate -db "../$DB_FILE" print importedDelegate || return 1
	log_success "Delegate chain printed"

	log_step "Signing CSR with onboard permission (no redirect)"
	run_cmd go run ./cmd delegate -db "../$DB_FILE" sign-csr "../$EPHEMERAL_DIR/delegate-csr.csr.pem" onboardOnly onboard SECP384R1 >"$EPHEMERAL_DIR/delegate-csr.onboard.pem" || return 1
	log_success "CSR signed with onboard-only permission"

	log_success "Delegate CSR Workflow test PASSED"
}

# (see delegate_test.go:TestSelfSignedDelegateRejected)
# Test: Rendezvous server verifies the to1d at TO0 (-rv-verify-to1d)
# Positive: Owner-signed and redirect-permitted delegate to1d are accepted.
# Negative: a delegate without fdo-ekt-permit-redirect is rejected at TO0.
test_rv_verify_to1d() {
	log_section "TEST: RV verifies to1d at TO0 (-rv-verify-to1d)"

	rm -f "$DB_FILE" "$CRED_FILE"

	log_step "Creating database with owner certs"
	start_server "-owner-certs"
	stop_server

	log_step "Creating delegates with and without the redirect permission"
	run_cmd go run ./cmd delegate -db "../$DB_FILE" create redirectDelegate onboard,redirect SECP384R1 ec384 || return 1
	run_cmd go run ./cmd delegate -db "../$DB_FILE" create noRedirectDelegate onboard SECP384R1 ec384 || return 1

	start_server "-owner-certs -rv-verify-to1d"

	log_step "Running DI"
	run_cmd go run ./cmd client -di "$SERVER_URL" || return 1
	local guid
	guid=$(sqlite3 "$DB_FILE" "SELECT hex(guid) FROM vouchers LIMIT 1;")
	log_success "DI completed (GUID $guid)"

	log_step "TO0 with Owner-signed to1d (should succeed)"
	run_cmd go run ./cmd server -http "$SERVER_ADDR" -db "../$DB_FILE" -to0 "$SERVER_URL" -to0-guid "$guid" || return 1
	log_success "Owner-signed to1d accepted"

	log_step "TO0 with redirect-permitted delegate (should succeed)"
	run_cmd go run ./cmd server -http "$SERVER_ADDR" -db "../$DB_FILE" -to0 "$SERVER_URL" -to0-guid "$guid" -rvDelegate redirectDelegate || return 1
	log_success "Delegate-signed to1d accepted"

	log_step "Expecting failure: TO0 with delegate lacking redirect permission"
	local to0_out
	if to0_out=$(cd examples && go run ./cmd server -http "$SERVER_ADDR" -db "../$DB_FILE" -to0 "$SERVER_URL" -to0-guid "$guid" -rvDelegate noRedirectDelegate 2>&1); then
		log_error "TO0 with a delegate lacking the redirect permission should have been rejected"
		return 1
	fi
	if ! grep -q "rendezvous blob rejected" <<<"$to0_out"; then
		log_error "TO0 failed, but not because the RV server rejected the to1d: $to0_out"
		return 1
	fi
	log_expected_failure "RV server rejected the to1d: $(grep -o 'rendezvous blob rejected[^"]*' <<<"$to0_out" | head -1)"

	log_step "Running TO1/TO2 with FDO 2.0 (uses the last accepted, delegate-signed to1d)"
	run_cmd go run ./cmd client -fdo-version 200 || return 1
	log_success "TO1/TO2 completed"

	stop_server
	log_success "RV verifies to1d test PASSED"
}

test_bad_delegate() {
	log_section "TEST: Bad Delegate Rejection (Security)"

	rm -f "$DB_FILE" "$CRED_FILE"

	log_step "Creating database with owner certs"
	start_server "-owner-certs"
	stop_server

	log_step "Creating legitimate delegate chain (SECP384R1 owner)"
	run_cmd go run ./cmd delegate -db "../$DB_FILE" create goodDelegate onboard,redirect SECP384R1 ec384 || return 1

	# Now try to create a delegate with a DIFFERENT owner key type
	# This simulates an attacker trying to use their own key
	log_step "Attempting to create delegate with wrong owner key (should fail or be rejected)"

	# Create a delegate rooted to SECP256R1 owner (different from SECP384R1 used for voucher)
	run_cmd go run ./cmd delegate -db "../$DB_FILE" create badDelegate onboard,redirect SECP256R1 ec256 || return 1

	# Start server with the GOOD delegate first to do DI
	start_server "-owner-certs -onboardDelegate goodDelegate"

	log_step "Running DI (creates voucher with SECP384R1 owner)"
	run_cmd go run ./cmd client -di "$SERVER_URL" || return 1
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
	test_fdo200_di200 || failed=1
	test_kex_fdo200 || failed=1
	test_delegate || failed=1
	test_delegate_fdo200 || failed=1
	test_delegate_csr || failed=1
	test_bad_delegate || failed=1
	test_rv_verify_to1d || failed=1

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

	# Clean up ephemeral files from previous test runs
	cleanup_ephemeral

	local rc=0
	case "$test_name" in
	basic)
		test_basic || rc=$?
		;;
	basic-reuse)
		test_basic_reuse || rc=$?
		;;
	rv-blob)
		test_rv_blob || rc=$?
		;;
	kex)
		test_kex || rc=$?
		;;
	fdo200)
		test_fdo200 || rc=$?
		;;
	fdo200-di200)
		test_fdo200_di200 || rc=$?
		;;
	kex-fdo200)
		test_kex_fdo200 || rc=$?
		;;
	delegate)
		test_delegate || rc=$?
		;;
	delegate-fdo200)
		test_delegate_fdo200 || rc=$?
		;;
	delegate-csr)
		test_delegate_csr || rc=$?
		;;
	bad-delegate)
		test_bad_delegate || rc=$?
		;;
	rv-verify-to1d)
		test_rv_verify_to1d || rc=$?
		;;
	all)
		test_all || rc=$?
		;;
	*)
		echo "Unknown test: $test_name"
		echo "Available tests: basic, basic-reuse, rv-blob, kex, fdo200, fdo200-di200, kex-fdo200, delegate, delegate-fdo200, delegate-csr, bad-delegate, rv-verify-to1d, all"
		exit 1
		;;
	esac
	exit $rc
}

main "$@"
