# Makefile
APP_NAME := agbero
BUILD_DIR := bin
SRC_DIR := ./cmd/agbero

# Version variables (will be injected via ldflags)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# LDFLAGS for version injection (matches GoReleaser)
LDFLAGS := -s -w -X "git.imaxinacion.net/aibox/agbero/internal/woos.Version=$(VERSION)" \
           -X "git.imaxinacion.net/aibox/agbero/internal/woos.Commit=$(COMMIT)" \
           -X "git.imaxinacion.net/aibox/agbero/internal/woos.Date=$(DATE)"

.PHONY: all build clean run install-deps build-all version help

all: build

help:
	@echo "Available targets:"
	@echo "  all          - Alias for 'build'"
	@echo "  build        - Build for current OS with version injection"
	@echo "  run          - Run interactively (Development helper)"
	@echo "  clean        - Clean build artifacts"
	@echo "  build-all    - Cross-compile for all platforms"
	@echo "  version      - Show current version info"
	@echo "  deps         - Install/update dependencies"
	@echo "  test         - Run tests"
	@echo "  test-verbose - Run tests with verbose output"
	@echo "  fmt          - Format Go code"
	@echo "  lint         - Lint Go code"
	@echo "  tidy         - Tidy go.mod"

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go mod download
	go mod tidy
	@echo "Dependencies installed"

# Build for current OS with version injection
build:
	@echo "Building $(APP_NAME) v$(VERSION) (commit: $(COMMIT))..."
	@mkdir -p $(BUILD_DIR)
	go build -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(APP_NAME) $(SRC_DIR)
	@echo "Done! Binary is in $(BUILD_DIR)/$(APP_NAME)"
	@$(BUILD_DIR)/$(APP_NAME) --version

# Run interactively (Development helper)
run:
	@echo "Running $(APP_NAME) in development mode..."
	go run $(SRC_DIR) run --dev --config ./etc/agbero/config.hcl

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	@echo "Clean complete"

# Cross-compile for release (matching GoReleaser targets)
build-all: clean
	@echo "Cross-compiling $(APP_NAME) v$(VERSION) for all platforms..."
	
	@echo "Building for Linux (amd64)..."
	GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(APP_NAME)-linux-amd64 $(SRC_DIR)
	
	@echo "Building for Linux (arm64)..."
	GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(APP_NAME)-linux-arm64 $(SRC_DIR)
	
	@echo "Building for Windows (amd64)..."
	GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(APP_NAME)-windows-amd64.exe $(SRC_DIR)
	
	@echo "Building for macOS (Intel)..."
	GOOS=darwin GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(APP_NAME)-darwin-amd64 $(SRC_DIR)
	
	@echo "Building for macOS (Apple Silicon)..."
	GOOS=darwin GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(APP_NAME)-darwin-arm64 $(SRC_DIR)
	
	@echo ""
	@echo "Build complete! Binaries in $(BUILD_DIR)/:"
	@ls -lh $(BUILD_DIR)/*

# Show version info
version:
	@echo "Version:    $(VERSION)"
	@echo "Commit:     $(COMMIT)"
	@echo "Build Date: $(DATE)"
	@echo "Go Version: $(shell go version)"

# Test targets
test:
	@echo "Running tests..."
	go test ./... -v -count=2

test-verbose:
	@echo "Running tests with verbose output..."
	go test ./... -v -count=1 -race

# Code quality
fmt:
	@echo "Formatting Go code..."
	gofmt -w -s .
	go fmt ./...

lint:
	@echo "Linting Go code..."
	golangci-lint run ./...

tidy:
	@echo "Tidying go.mod..."
	go mod tidy

# Special target for GoReleaser snapshot builds
# This matches GoReleaser's behavior for local testing
snapshot:
	@echo "Building snapshot release..."
	VERSION=$(VERSION)-SNAPSHOT $(MAKE) build-all

# Quick check of what GoReleaser would do
goreleaser-check:
	@echo "Checking GoReleaser configuration..."
	goreleaser check
	@echo ""
	@echo "Dry-run GoReleaser build..."
	goreleaser release --snapshot --clean --skip=publish

# Generate changelog (optional, if you have git-chglog)
changelog:
	git-chglog -o CHANGELOG.md

# Development helpers
dev: deps build
	@echo "Starting development server..."
	./$(BUILD_DIR)/$(APP_NAME) run --dev

# Check for updates in dependencies
update-deps:
	@echo "Updating dependencies..."
	go get -u ./...
	go mod tidy
	@echo "Dependencies updated"