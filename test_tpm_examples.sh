#!/bin/bash
#
# FDO TPM Integration Tests
#
# Runs DI and onboarding (TO1/TO2) flows using a TPM for device credential
# storage. Supports both hardware TPM and software TPM (swtpm) modes.
#
# The server runs in standard (non-TPM) mode — only the client uses TPM.
#
# Modes (set via TPM_MODE env var):
#   hw  - Hardware TPM (default). Requires /dev/tpmrm0 access.
#   sim - Software TPM via swtpm. Requires swtpm installed.
#
# Prerequisites:
#   - sqlite3 must be installed (for GUID extraction)
#   - Hardware mode: /dev/tpmrm0 readable/writable by current user
#   - Simulator mode: swtpm installed (apt install swtpm)
#   - FDO_TPM_OWNER_HIERARCHY=1 is set automatically (Linux userspace
#     cannot use Platform hierarchy)
#
# Usage: ./test_tpm_examples.sh [test_name]
#        TPM_MODE=sim ./test_tpm_examples.sh [test_name]
#   test_name: basic, basic-reuse, fdo200, all (default: all)
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
TPM_CLIENT=""
SERVER_PID=""
SWTPM_PID=""

# TPM mode: "hw" for hardware TPM, "sim" for software TPM (swtpm)
TPM_MODE="${TPM_MODE:-hw}"

# TPM device path — only used in hw mode (override with TPM_DEVICE env var)
TPM_DEVICE="${TPM_DEVICE:-/dev/tpmrm0}"

# swtpm state directory and socket path
SWTPM_STATE="$EPHEMERAL_DIR/swtpm-state"
SWTPM_SOCK="$EPHEMERAL_DIR/swtpm.sock"

# Both modes build with -tags=tpm (swtpm is an external TPM, not in-process sim)
TPM_BUILD_TAG="tpm"

if [ "$TPM_MODE" = "sim" ]; then
	TPM_LABEL="swtpm (software)"
else
	TPM_LABEL="hardware ($TPM_DEVICE)"
fi

# Force Owner hierarchy — Platform hierarchy is locked on Linux after boot
export FDO_TPM_OWNER_HIERARCHY=1

# Cleanup function
cleanup() {
	if [ -n "$SERVER_PID" ]; then
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
	fi
	pkill -f "go-build.*server" 2>/dev/null || true
	pkill -f "examples/cmd server" 2>/dev/null || true
	pkill -f "cmd server" 2>/dev/null || true

	# Stop swtpm if running
	if [ -n "$SWTPM_PID" ]; then
		kill "$SWTPM_PID" 2>/dev/null || true
		wait "$SWTPM_PID" 2>/dev/null || true
	fi

	sleep 2
	pkill -9 -f "go-build.*server" 2>/dev/null || true
	pkill -9 -f "examples/cmd server" 2>/dev/null || true
	pkill -9 -f "cmd server" 2>/dev/null || true
}

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
	echo -e "${GREEN}  $1${NC}"
}

log_error() {
	echo -e "${RED}  $1${NC}"
}

run_cmd() {
	echo -e "${YELLOW}\$ $*${NC}"
	if ! (cd examples && "$@"); then
		log_error "Command failed: $*"
		return 1
	fi
}

# Run the pre-built TPM client binary
# In sim mode, FDO_TPM_DEVICE points to the swtpm socket
run_tpm_client() {
	echo -e "${YELLOW}\$ $TPM_CLIENT $*${NC}"
	if [ "$TPM_MODE" = "sim" ]; then
		if ! FDO_TPM_DEVICE="$SWTPM_SOCK" "$TPM_CLIENT" "$@"; then
			log_error "TPM client command failed: $*"
			return 1
		fi
	else
		if ! "$TPM_CLIENT" "$@"; then
			log_error "TPM client command failed: $*"
			return 1
		fi
	fi
}

start_server() {
	local flags="$1"
	log_step "Starting server with flags: $flags"

	pkill -f "go-build.*server" 2>/dev/null || true
	pkill -f "examples/cmd server" 2>/dev/null || true
	sleep 2

	local retries=5
	while [ $retries -gt 0 ]; do
		if ! lsof -i :9999 >/dev/null 2>&1 && ! netstat -tulpn 2>/dev/null | grep :9999 >/dev/null; then
			break
		fi
		sleep 1
		retries=$((retries - 1))
	done

	mkdir -p "$EPHEMERAL_DIR"

	# shellcheck disable=SC2086
	log_step "go run ./cmd server -http \"$SERVER_ADDR\" -db \"../$DB_FILE\" $flags"
	# shellcheck disable=SC2086
	(cd examples && go run ./cmd server -http "$SERVER_ADDR" -db "../$DB_FILE" $flags >/tmp/fdo_tpm_server.log 2>&1) &
	SERVER_PID=$!

	local retries=15
	while [ $retries -gt 0 ]; do
		if grep -q "Listening" /tmp/fdo_tpm_server.log 2>/dev/null; then
			sleep 0.5
			if nc -z 127.0.0.1 9999 2>/dev/null || (echo >/dev/tcp/127.0.0.1/9999) 2>/dev/null; then
				log_success "Server started (PID: $SERVER_PID)"
				return 0
			fi
			if ! kill -0 "$SERVER_PID" 2>/dev/null; then
				log_error "Server process died after logging Listening"
				cat /tmp/fdo_tpm_server.log 2>/dev/null || true
				return 1
			fi
		fi
		if ! kill -0 "$SERVER_PID" 2>/dev/null; then
			log_error "Server process died"
			cat /tmp/fdo_tpm_server.log 2>/dev/null || true
			return 1
		fi
		sleep 1
		retries=$((retries - 1))
	done

	log_error "Server failed to start (timeout)"
	cat /tmp/fdo_tpm_server.log 2>/dev/null || true
	return 1
}

stop_server() {
	log_step "Stopping server"
	if [ -n "$SERVER_PID" ]; then
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
	fi
	pkill -f "go-build.*server" 2>/dev/null || true
	pkill -f "examples/cmd server" 2>/dev/null || true
	SERVER_PID=""

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

# Build the client binary with TPM support
build_tpm_client() {
	log_step "Building client with -tags=$TPM_BUILD_TAG"
	mkdir -p "$EPHEMERAL_DIR"
	TPM_CLIENT="$(pwd)/$EPHEMERAL_DIR/fdo-tpm-client"
	(cd examples && go build -tags="$TPM_BUILD_TAG" -o "$TPM_CLIENT" ./cmd)
	log_success "TPM client built: $TPM_CLIENT"
}

# Start swtpm (sim mode only)
start_swtpm() {
	log_step "Starting swtpm"
	rm -rf "$SWTPM_STATE"
	mkdir -p "$SWTPM_STATE"
	rm -f "$SWTPM_SOCK"

	swtpm socket \
		--tpm2 \
		--tpmstate "dir=$SWTPM_STATE" \
		--server "type=unixio,path=$SWTPM_SOCK" \
		--ctrl "type=unixio,path=$SWTPM_STATE/ctrl.sock" \
		--flags startup-clear \
		--log "level=0" >/dev/null 2>&1 &
	SWTPM_PID=$!

	# Wait for socket to appear
	local retries=10
	while [ $retries -gt 0 ]; do
		if [ -S "$SWTPM_SOCK" ]; then
			log_success "swtpm started (PID: $SWTPM_PID, socket: $SWTPM_SOCK)"
			return 0
		fi
		if ! kill -0 "$SWTPM_PID" 2>/dev/null; then
			log_error "swtpm process died"
			return 1
		fi
		sleep 0.5
		retries=$((retries - 1))
	done

	log_error "swtpm failed to start (socket not created)"
	return 1
}

# Stop and restart swtpm with fresh state (for test isolation)
restart_swtpm() {
	if [ -n "$SWTPM_PID" ]; then
		kill "$SWTPM_PID" 2>/dev/null || true
		wait "$SWTPM_PID" 2>/dev/null || true
		SWTPM_PID=""
	fi
	start_swtpm
}

# Clear all FDO state from the TPM
tpm_clear() {
	log_step "Clearing FDO credentials from TPM"
	run_tpm_client client -tpm-clear
	log_success "TPM FDO state cleared"
}

# Show TPM credential state (for diagnostics)
tpm_show() {
	log_step "TPM credential state:"
	run_tpm_client client -tpm-show || true
}

# Verify that no cred.bin file was created (TPM mode should not write files)
verify_no_cred_file() {
	if [ -f "$EPHEMERAL_DIR/cred.bin" ]; then
		log_error "cred.bin exists — TPM mode should not write credential files"
		return 1
	fi
	log_success "No cred.bin file (credentials stored in TPM NV only)"
}

# =============================================================================
# Test: Basic TPM DI + Onboarding
# =============================================================================
test_tpm_basic() {
	log_section "TEST: TPM Basic DI + Onboarding"

	rm -f "$DB_FILE"
	if [ "$TPM_MODE" = "sim" ]; then
		restart_swtpm || return 1
	fi
	tpm_clear || return 1

	start_server "" || return 1

	log_step "Running DI (Device Initialization) via TPM"
	run_tpm_client client -di "$SERVER_URL" || {
		stop_server
		return 1
	}
	log_success "DI completed — credentials stored in TPM NV"

	tpm_show
	verify_no_cred_file || {
		stop_server
		return 1
	}

	log_step "Verifying DAK was persisted"
	run_tpm_client client -tpm-export-dak || {
		stop_server
		return 1
	}
	log_success "DAK public key exported"

	log_step "Running TO1/TO2 (Transfer Ownership) via TPM"
	run_tpm_client client || {
		stop_server
		return 1
	}
	log_success "TO1/TO2 completed"

	tpm_show

	stop_server
	log_success "TPM Basic DI + Onboarding test PASSED"
}

# =============================================================================
# Test: TPM DI + Onboarding with Credential Reuse
# =============================================================================
test_tpm_basic_reuse() {
	log_section "TEST: TPM DI + Onboarding with Credential Reuse"

	rm -f "$DB_FILE"
	if [ "$TPM_MODE" = "sim" ]; then
		restart_swtpm || return 1
	fi
	tpm_clear || return 1

	start_server "-reuse-cred" || return 1

	log_step "Running DI via TPM"
	run_tpm_client client -di "$SERVER_URL" || {
		stop_server
		return 1
	}
	log_success "DI completed"

	tpm_show

	log_step "Running TO1/TO2 (first onboard)"
	run_tpm_client client || {
		stop_server
		return 1
	}
	log_success "First TO1/TO2 completed"

	log_step "Running TO1/TO2 again (credential reuse)"
	run_tpm_client client || {
		stop_server
		return 1
	}
	log_success "Second TO1/TO2 completed (credential reuse)"

	tpm_show
	verify_no_cred_file || {
		stop_server
		return 1
	}

	stop_server
	log_success "TPM Credential Reuse test PASSED"
}

# =============================================================================
# Test: TPM DI + Onboarding with FDO 2.0 Protocol
# =============================================================================
test_tpm_fdo200() {
	log_section "TEST: TPM DI + Onboarding (FDO 2.0)"

	rm -f "$DB_FILE"
	if [ "$TPM_MODE" = "sim" ]; then
		restart_swtpm || return 1
	fi
	tpm_clear || return 1

	start_server "-reuse-cred" || return 1

	log_step "Running DI via TPM"
	run_tpm_client client -di "$SERVER_URL" || {
		stop_server
		return 1
	}
	log_success "DI completed"

	tpm_show

	log_step "Running TO1/TO2 with FDO 2.0"
	run_tpm_client client -fdo-version 200 || {
		stop_server
		return 1
	}
	log_success "TO1/TO2 completed with FDO 2.0"

	log_step "Running TO1/TO2 again with FDO 2.0 (credential reuse)"
	run_tpm_client client -fdo-version 200 || {
		stop_server
		return 1
	}
	log_success "Second TO1/TO2 completed with FDO 2.0 (reuse)"

	tpm_show
	verify_no_cred_file || {
		stop_server
		return 1
	}

	stop_server
	log_success "TPM FDO 2.0 test PASSED"
}

# =============================================================================
# Run all TPM tests
# =============================================================================
test_all() {
	local failed=0

	test_tpm_basic || failed=1
	test_tpm_basic_reuse || failed=1
	test_tpm_fdo200 || failed=1

	echo ""
	if [ $failed -eq 0 ]; then
		log_section "ALL TPM TESTS PASSED"
	else
		log_section "SOME TPM TESTS FAILED"
		return 1
	fi
}

# =============================================================================
# Main
# =============================================================================
main() {
	local test_name="${1:-all}"

	log_section "FDO TPM Integration Tests"
	echo "Test: $test_name"
	echo "TPM mode: $TPM_LABEL"
	echo "Working directory: $(pwd)"

	# Ensure we're in the right directory
	if [ ! -f "go.mod" ]; then
		log_error "Must be run from go-fdo root directory"
		exit 1
	fi

	# Check for sqlite3
	if ! command -v sqlite3 &>/dev/null; then
		log_error "sqlite3 is required but not installed"
		exit 1
	fi

	# Hardware mode: check for TPM device
	if [ "$TPM_MODE" != "sim" ]; then
		if [ ! -e "$TPM_DEVICE" ]; then
			log_error "TPM device not found: $TPM_DEVICE"
			echo "  Set TPM_DEVICE to the correct path, or ensure a TPM is available."
			echo "  Common paths: /dev/tpmrm0, /dev/tpm0"
			echo "  Or use simulator mode: TPM_MODE=sim $0 $test_name"
			exit 1
		fi

		if [ ! -r "$TPM_DEVICE" ] || [ ! -w "$TPM_DEVICE" ]; then
			log_error "Cannot read/write TPM device: $TPM_DEVICE"
			echo "  Try: sudo chmod 666 $TPM_DEVICE"
			echo "  Or run as root / with appropriate group membership."
			exit 1
		fi

		log_success "TPM device accessible: $TPM_DEVICE"
	else
		# Simulator mode: check for swtpm
		if ! command -v swtpm &>/dev/null; then
			log_error "swtpm is required for simulator mode but not installed"
			echo "  Install with: sudo apt install swtpm swtpm-tools"
			exit 1
		fi
		log_success "swtpm found: $(command -v swtpm)"
	fi

	cleanup_ephemeral
	build_tpm_client

	case "$test_name" in
	basic)
		test_tpm_basic
		;;
	basic-reuse)
		test_tpm_basic_reuse
		;;
	fdo200)
		test_tpm_fdo200
		;;
	all)
		test_all
		;;
	*)
		echo "Unknown test: $test_name"
		echo "Available tests: basic, basic-reuse, fdo200, all"
		exit 1
		;;
	esac
}

main "$@"
