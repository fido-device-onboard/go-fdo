.PHONY: all setup build test test-unit test-integration lint lint-go lint-shell clean help

# Default target
all: lint test

# Initialize Go workspace (run once after clone)
setup:
	@if [ ! -f go.work ]; then \
		echo "Initializing Go workspace..."; \
		go work init; \
		go work use -r .; \
	else \
		echo "Go workspace already initialized (go.work exists)"; \
	fi

# Build the project
build:
	go build ./...

# Run all tests
test: test-unit test-integration

# Run Go unit tests (replicates GitHub Actions exactly)
test-unit:
	@echo "=== Testing base library ==="
	go work init 2>/dev/null || true
	go work use -r . 2>/dev/null || true
	go test -v ./...
	@echo ""
	@echo "=== Testing FSIM ==="
	go test -v ./fsim/...
	@echo ""
	@echo "=== Testing sqlite ==="
	go test -v ./sqlite/...
	@echo ""
	@echo "=== Testing TPM ==="
	go test -v ./tpm/...
	@echo ""
	@echo "=== Testing examples ==="
	go test -v ./examples/...

# Run integration/example tests
test-integration:
	./test_examples.sh

# Run all linters
lint:
	@echo "=== Running Go linter (will show issues but not fail) ==="
	-$(MAKE) lint-go
	@echo ""
	@echo "=== Running shell script linters ==="
	$(MAKE) lint-shell

# Run Go linter (replicates GitHub Actions exactly)
lint-go:
	@echo "=== Linting base library ==="
	go work init 2>/dev/null || true
	go work use -r . 2>/dev/null || true
	-golangci-lint run ./... || true
	@echo ""
	@echo "=== Linting FSIM ==="
	-golangci-lint run ./fsim/... || true
	@echo ""
	@echo "=== Linting sqlite ==="
	-golangci-lint run ./sqlite/... || true
	@echo ""
	@echo "=== Linting TPM ==="
	-golangci-lint run ./tpm/... || true
	@echo ""
	@echo "=== Linting examples ==="
	-golangci-lint run ./examples/... || true

# Run shell script linters (format + static analysis)
lint-shell:
	find . -name '*.sh' -o -name '*.bash' | xargs shfmt -d
	@if command -v shellcheck >/dev/null 2>&1; then \
		find . -name '*.sh' -o -name '*.bash' | xargs shellcheck; \
	else \
		echo "Warning: shellcheck not installed, skipping"; \
	fi

# Fix shell script formatting
lint-shell-fix:
	find . -name '*.sh' -o -name '*.bash' | xargs shfmt -w

# Clean test artifacts
clean:
	rm -f test.db cred.bin voucher.pem
	rm -f *.fdo *.key *.bin
	rm -rf fdo.download_*

# Show help
help:
	@echo "Available targets:"
	@echo "  setup            - Initialize Go workspace (run once after clone)"
	@echo "  all              - Run lint and test (default)"
	@echo "  build            - Build the project"
	@echo "  test             - Run all tests (unit + integration)"
	@echo "  test-unit        - Run Go unit tests"
	@echo "  test-integration - Run integration tests (test_examples.sh)"
	@echo "  lint             - Run all linters (Go + shell)"
	@echo "  lint-go          - Run golangci-lint"
	@echo "  lint-shell       - Check shell script formatting"
	@echo "  lint-shell-fix   - Fix shell script formatting"
	@echo "  clean            - Remove test artifacts"
	@echo "  help             - Show this help"
