# Security Tracker Agent Makefile

# Variables
BINARY_NAME=sec-tracker
VERSION?=1.0.0
BUILD_DIR=build
DIST_DIR=dist
GO_VERSION=1.21

# Build flags
LDFLAGS=-ldflags "-X main.Version=${VERSION} -X main.BuildTime=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)"
GCFLAGS=-gcflags="all=-trimpath=$(PWD)"
ASMFLAGS=-asmflags="all=-trimpath=$(PWD)"

# Default target
.PHONY: all
all: clean test build

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR) $(DIST_DIR)
	@rm -f $(BINARY_NAME)

# Download dependencies
.PHONY: deps
deps:
	@echo "Downloading dependencies..."
	@go mod download
	@go mod verify

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	@go test -v ./...

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	@go test -v -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html

# Build for current platform
.PHONY: build
build: deps
	@echo "Building $(BINARY_NAME)..."
	@go build $(LDFLAGS) $(GCFLAGS) $(ASMFLAGS) -o $(BINARY_NAME) .

# Build for Linux x86_64
.PHONY: build-linux
build-linux: deps
	@echo "Building for Linux x86_64..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=linux GOARCH=amd64 go build $(LDFLAGS) $(GCFLAGS) $(ASMFLAGS) \
		-o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .

# Build for Linux ARM64
.PHONY: build-linux-arm64
build-linux-arm64: deps
	@echo "Building for Linux ARM64..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=linux GOARCH=arm64 go build $(LDFLAGS) $(GCFLAGS) $(ASMFLAGS) \
		-o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 .

# Build for all supported platforms
.PHONY: build-all
build-all: build-linux build-linux-arm64

# Install locally (requires sudo)
.PHONY: install
install: build
	@echo "Installing $(BINARY_NAME)..."
	@sudo chmod +x scripts/install.sh
	@sudo ./scripts/install.sh

# Create distribution packages
.PHONY: dist
dist: build-all
	@echo "Creating distribution packages..."
	@mkdir -p $(DIST_DIR)
	
	# Linux x86_64 package
	@mkdir -p $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)-linux-amd64
	@cp $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)-linux-amd64/$(BINARY_NAME)
	@cp config.json $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)-linux-amd64/
	@cp -r scripts $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)-linux-amd64/
	@cp README.md $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)-linux-amd64/
	@cd $(DIST_DIR) && tar -czf $(BINARY_NAME)-$(VERSION)-linux-amd64.tar.gz $(BINARY_NAME)-$(VERSION)-linux-amd64
	
	# Linux ARM64 package
	@mkdir -p $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)-linux-arm64
	@cp $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)-linux-arm64/$(BINARY_NAME)
	@cp config.json $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)-linux-arm64/
	@cp -r scripts $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)-linux-arm64/
	@cp README.md $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)-linux-arm64/
	@cd $(DIST_DIR) && tar -czf $(BINARY_NAME)-$(VERSION)-linux-arm64.tar.gz $(BINARY_NAME)-$(VERSION)-linux-arm64
	
	@echo "Distribution packages created in $(DIST_DIR)/"

# Check if Go is installed and version is correct
.PHONY: check-go
check-go:
	@if ! command -v go >/dev/null 2>&1; then \
		echo "Go is not installed. Please install Go $(GO_VERSION) or later."; \
		exit 1; \
	fi
	@GO_VERSION_INSTALLED=$$(go version | cut -d' ' -f3 | sed 's/go//'); \
	if [ "$$(printf '%s\n' "$(GO_VERSION)" "$$GO_VERSION_INSTALLED" | sort -V | head -n1)" != "$(GO_VERSION)" ]; then \
		echo "Go version $$GO_VERSION_INSTALLED is too old. Please upgrade to $(GO_VERSION) or later."; \
		exit 1; \
	fi

# Lint code
.PHONY: lint
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		echo "Running golangci-lint..."; \
		golangci-lint run; \
	else \
		echo "golangci-lint not found. Running go vet..."; \
		go vet ./...; \
	fi

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	@go fmt ./...

# Security scan
.PHONY: security
security:
	@if command -v gosec >/dev/null 2>&1; then \
		echo "Running security scan..."; \
		gosec ./...; \
	else \
		echo "gosec not found. Install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"; \
	fi

# Run development server (for testing)
.PHONY: dev
dev: build
	@echo "Running development instance..."
	@sudo ./$(BINARY_NAME)

# Local mode testing targets
.PHONY: test-local
test-local: build
	@echo "Testing local mode (human-readable)..."
	@./$(BINARY_NAME) -local -oneshot

.PHONY: test-local-json
test-local-json: build
	@echo "Testing local mode (JSON format)..."
	@./$(BINARY_NAME) -local -oneshot -json

.PHONY: test-local-monitor
test-local-monitor: build
	@echo "Testing continuous local monitoring..."
	@echo "Press Ctrl+C to stop..."
	@./$(BINARY_NAME) -local

.PHONY: test-local-compact
test-local-compact: build
	@echo "Testing compact local output..."
	@echo "Press Ctrl+C to stop..."
	@echo '{"local_output": {"compact_output": true}}' > /tmp/test-config.json
	@./$(BINARY_NAME) -local -config /tmp/test-config.json
	@rm -f /tmp/test-config.json

.PHONY: demo
demo: build
	@echo "=== Security Tracker Agent Demo ==="
	@echo ""
	@echo "1. Version information:"
	@./$(BINARY_NAME) -version
	@echo ""
	@echo "2. System scan (human-readable):"
	@./$(BINARY_NAME) -local -oneshot
	@echo ""
	@echo "3. System scan (JSON format):"
	@./$(BINARY_NAME) -local -oneshot -json | head -20
	@echo "..."
	@echo ""
	@echo "Demo completed!"

# Generate mocks (if using mockery)
.PHONY: mocks
mocks:
	@if command -v mockery >/dev/null 2>&1; then \
		echo "Generating mocks..."; \
		mockery --all; \
	else \
		echo "mockery not found. Install with: go install github.com/vektra/mockery/v2@latest"; \
	fi

# Uninstall
.PHONY: uninstall
uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	@sudo systemctl stop sec-tracker 2>/dev/null || true
	@sudo systemctl disable sec-tracker 2>/dev/null || true
	@sudo rm -f /etc/systemd/system/sec-tracker.service
	@sudo rm -f /usr/local/bin/sec-tracker
	@sudo rm -rf /etc/sec-tracker
	@sudo rm -rf /var/log/sec-tracker
	@sudo rm -rf /var/lib/sec-tracker
	@sudo userdel sec-tracker 2>/dev/null || true
	@sudo groupdel sec-tracker 2>/dev/null || true
	@sudo systemctl daemon-reload
	@echo "Uninstall completed"

# Docker build
.PHONY: docker
docker:
	@echo "Building Docker image..."
	@docker build -t $(BINARY_NAME):$(VERSION) .

# Help
.PHONY: help
help:
	@echo "Security Tracker Agent - Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  all              - Clean, test, and build"
	@echo "  build            - Build for current platform"
	@echo "  build-linux      - Build for Linux x86_64"
	@echo "  build-linux-arm64- Build for Linux ARM64"
	@echo "  build-all        - Build for all platforms"
	@echo "  clean            - Clean build artifacts"
	@echo "  deps             - Download dependencies"
	@echo "  test             - Run tests"
	@echo "  test-coverage    - Run tests with coverage"
	@echo "  lint             - Lint code"
	@echo "  fmt              - Format code"
	@echo "  security         - Run security scan"
	@echo "  install          - Install locally (requires sudo)"
	@echo "  uninstall        - Uninstall from system"
	@echo "  dist             - Create distribution packages"
	@echo "  dev              - Run development instance"
	@echo "  docker           - Build Docker image"
	@echo "  check-go         - Check Go installation"
	@echo "  mocks            - Generate test mocks"
	@echo ""
	@echo "Local mode testing:"
	@echo "  test-local       - Test local mode (one-shot, human-readable)"
	@echo "  test-local-json  - Test local mode (one-shot, JSON)"
	@echo "  test-local-monitor - Test continuous monitoring"
	@echo "  test-local-compact - Test compact output format"
	@echo "  demo             - Run demo showing all features"
	@echo ""
	@echo "Examples:"
	@echo "  make build       - Build for current platform"
	@echo "  make install     - Build and install"
	@echo "  make demo        - Quick demonstration"
	@echo "  make test-local  - Test local output mode" 