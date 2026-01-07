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

run_cmd() {
    echo -e "${YELLOW}\$ $*${NC}"
    (cd examples && "$@")
}

start_server() {
    local flags="$1"
    log_step "Starting server with flags: $flags"
    
    # Kill any existing server processes
    pkill -f "go-build.*server" 2>/dev/null || true
    pkill -f "examples/cmd server" 2>/dev/null || true
    sleep 1
    
    # Start server in background, redirecting output to a temp file
    (cd examples && go run ./cmd server -http "$SERVER_ADDR" -db "../$DB_FILE" $flags > /tmp/fdo_server.log 2>&1) &
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

# Test: RV Blob Registration (from README.md)
test_rv_blob() {
    log_section "TEST: RV Blob Registration"
    
    rm -f "$DB_FILE" "$CRED_FILE"
    
    start_server "-to0 $SERVER_URL"
    
    log_step "Running DI"
    run_cmd go run ./cmd client -di "$SERVER_URL"
    log_success "DI completed"
    
    log_step "Getting device GUID"
    GUID=$(sqlite3 "$DB_FILE" 'select hex(guid) from vouchers limit 1;')
    echo "Device GUID: $GUID"
    
    log_step "Verifying TO1 fails (not registered)"
    if (cd examples && go run ./cmd client -rv-only 2>&1) | grep -q "ERROR"; then
        log_success "TO1 correctly failed (not registered)"
    else
        log_error "TO1 should have failed but succeeded"
        return 1
    fi
    
    log_step "Registering RV blob (server still running)"
    run_cmd go run ./cmd server -to0 "$SERVER_URL" -to0-guid "$GUID" -db "./$DB_FILE"
    log_success "RV blob registered"
    
    log_step "Verifying TO1 now succeeds"
    run_cmd go run ./cmd client -rv-only
    log_success "TO1 succeeded after registration"
    
    stop_server
    log_success "RV Blob Registration test PASSED"
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
test_delegate() {
    log_section "TEST: Delegate Support (FDO 1.01)"
    
    rm -f "$DB_FILE" "$CRED_FILE"
    
    log_step "Creating database with owner certs"
    run_cmd go run ./cmd server -http "$SERVER_ADDR" -db "./$DB_FILE" -owner-certs &
    SERVER_PID=$!
    sleep 2
    stop_server
    
    log_step "Creating delegate chain"
    run_cmd go run ./cmd delegate -db "$DB_FILE" create myDelegate onboard,redirect SECP384R1 ec384 ec384
    log_success "Delegate chain created"
    
    log_step "Listing delegate chains"
    run_cmd go run ./cmd delegate -db "$DB_FILE" list
    
    log_step "Printing delegate chain"
    run_cmd go run ./cmd delegate -db "$DB_FILE" print myDelegate
    
    # Start server with delegate and TO0 support (self-registration)
    start_server "-owner-certs -onboardDelegate myDelegate -reuse-cred -to0 $SERVER_URL"
    
    log_step "Running DI"
    run_cmd go run ./cmd client -di "$SERVER_URL"
    log_success "DI completed"
    
    log_step "Getting device GUID"
    GUID=$(sqlite3 "$DB_FILE" 'select hex(guid) from vouchers limit 1;')
    echo "Device GUID: $GUID"
    
    log_step "Registering RV blob with delegate"
    run_cmd go run ./cmd server -db "$DB_FILE" -to0 "$SERVER_URL" -rvDelegate myDelegate -to0-guid "$GUID"
    log_success "RV blob registered with delegate"
    
    log_step "Running TO1 only (verify RV registration)"
    run_cmd go run ./cmd client -rv-only
    log_success "TO1 succeeded"
    
    log_step "Running full TO1/TO2 with delegate"
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
    run_cmd go run ./cmd server -http "$SERVER_ADDR" -db "./$DB_FILE" -owner-certs &
    SERVER_PID=$!
    sleep 2
    stop_server
    
    log_step "Creating delegate chain"
    run_cmd go run ./cmd delegate -db "$DB_FILE" create myDelegate onboard,redirect SECP384R1 ec384 ec384
    log_success "Delegate chain created"
    
    # Start server with delegate and TO0 support (self-registration)
    start_server "-owner-certs -onboardDelegate myDelegate -reuse-cred -to0 $SERVER_URL"
    
    log_step "Running DI"
    run_cmd go run ./cmd client -di "$SERVER_URL"
    log_success "DI completed"
    
    log_step "Getting device GUID"
    GUID=$(sqlite3 "$DB_FILE" 'select hex(guid) from vouchers limit 1;')
    echo "Device GUID: $GUID"
    
    log_step "Registering RV blob with delegate"
    run_cmd go run ./cmd server -db "$DB_FILE" -to0 "$SERVER_URL" -rvDelegate myDelegate -to0-guid "$GUID"
    log_success "RV blob registered with delegate"
    
    log_step "Running TO1/TO2 with FDO 2.0 and delegate"
    run_cmd go run ./cmd client -fdo-version 200
    log_success "TO1/TO2 completed with FDO 2.0 and delegate"
    
    log_step "Running TO1/TO2 again (credential reuse with delegate)"
    run_cmd go run ./cmd client -fdo-version 200
    log_success "TO1/TO2 completed with FDO 2.0 (credential reuse)"
    
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
    if ! command -v sqlite3 &> /dev/null; then
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
