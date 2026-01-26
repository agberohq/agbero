APP_NAME := agbero
BUILD_DIR := bin
SRC_DIR := ./cmd/agbero

# Remote
PLAY_HOST ?= aibox.play
PLAY_USER ?= root
PLAY_PATH ?= /usr/local/bin
PLAY_OS   ?= linux
PLAY_ARCH ?= amd64



# Git remote for pushing tags
REMOTE ?= origin

# --------------------------
# Install Configuration
# --------------------------

# 1. Detect Go Bin path via 'go env' (more reliable than shell env)
GO_ENV_GOPATH := $(shell go env GOPATH)
GO_ENV_GOBIN  := $(shell go env GOBIN)

# 2. Determine BINDIR (Installation Directory)
# Logic:
#   A. If PREFIX is explicitly set (make install PREFIX=/usr/local), use $(PREFIX)/bin.
#   B. Else if GOBIN is set (go env GOBIN), use that.
#   C. Else if GOPATH is set (go env GOPATH), use $(GOPATH)/bin.
#   D. Fallback to /usr/local/bin.

ifdef PREFIX
	BINDIR := $(PREFIX)/bin
else
	ifneq ($(GO_ENV_GOBIN),)
		BINDIR := $(GO_ENV_GOBIN)
	else ifneq ($(GO_ENV_GOPATH),)
		BINDIR := $(GO_ENV_GOPATH)/bin
	else
		BINDIR := /usr/local/bin
	endif
endif

# Release version for tagging and GoReleaser
RELEASE_VERSION ?=

# Version variables
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# LDFLAGS for version injection
LDFLAGS := -s -w -X "git.imaxinacion.net/aibox/agbero/internal/woos.Version=$(VERSION)" \
           -X "git.imaxinacion.net/aibox/agbero/internal/woos.Commit=$(COMMIT)" \
           -X "git.imaxinacion.net/aibox/agbero/internal/woos.Date=$(DATE)"

.PHONY: all build clean run install build-all version help \
        deps test test-verbose fmt lint tidy snapshot goreleaser-check changelog dev update-deps \
        ensure-clean ensure-release-version tag release release-dry play

all: build

help:
	@echo "Available targets:"
	@echo "  all            - Alias for 'build'"
	@echo "  build          - Build for current OS with version injection"
	@echo "  install        - Install binary to $(BINDIR)"
	@echo "                   (Use 'make install PREFIX=/usr/local' to force system install)"
	@echo "  run            - Run interactively (Development helper)"
	@echo "  clean          - Clean build artifacts"
	@echo "  build-all      - Cross-compile for all platforms"
	@echo "  version        - Show current version info"
	@echo "  deps           - Install/update dependencies"
	@echo "  test           - Run tests"
	@echo "  test-verbose   - Run tests with verbose output"
	@echo "  fmt            - Format Go code"
	@echo "  lint           - Lint Go code"
	@echo "  tidy           - Tidy go.mod"
	@echo "  snapshot       - Snapshot build (local testing)"
	@echo "  goreleaser-check - GoReleaser check + snapshot dry-run build"
	@echo "  changelog      - Generate changelog (requires git-chglog)"
	@echo "  dev            - deps + build then run dev"
	@echo "  update-deps    - Update Go deps"
	@echo ""
	@echo "Release targets:"
	@echo "  ensure-clean   - Fail if repo is dirty"
	@echo "  tag            - Force (re)create RELEASE_VERSION tag at HEAD and push"
	@echo "  release        - tag + goreleaser release --clean"
	@echo "  release-dry    - tag + goreleaser release --clean --skip=publish"
	@echo ""
	@echo "Release usage:"
	@echo "  make release RELEASE_VERSION=0.0.2"
	@echo "  make release-dry RELEASE_VERSION=0.0.2"

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

# Install to BINDIR (Autodetected GOPATH or Custom PREFIX)
install: build
	@echo "Installing binary to $(DESTDIR)$(BINDIR)..."
	@mkdir -p $(DESTDIR)$(BINDIR)
	@install -m 755 $(BUILD_DIR)/$(APP_NAME) $(DESTDIR)$(BINDIR)/$(APP_NAME)
	@echo "Installation complete."

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

# Generate changelog
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

# --------------------------
# Release helpers (GoReleaser)
# --------------------------

ensure-clean:
	@echo "Checking git working tree..."
	@git diff --quiet || (echo "Error: working tree has tracked changes. Commit or stash them."; exit 1)
	@test -z "$$(git status --porcelain)" || (echo "Error: working tree has uncommitted/untracked files:"; git status --porcelain; exit 1)
	@echo "Git working tree is clean"

ensure-release-version:
	@test -n "$(RELEASE_VERSION)" || (echo "Error: set RELEASE_VERSION, e.g. make release RELEASE_VERSION=0.0.2"; exit 1)

tag: ensure-clean ensure-release-version
	@if git rev-parse "$(RELEASE_VERSION)" >/dev/null 2>&1; then \
		echo "Error: tag $(RELEASE_VERSION) already exists. Bump the version."; \
		exit 1; \
	fi
	@echo "Creating tag $(RELEASE_VERSION) at HEAD $$(git rev-parse --short HEAD)"
	@git tag -a $(RELEASE_VERSION) -m "v$(RELEASE_VERSION)"
	@git push $(REMOTE) $(RELEASE_VERSION)

release: tag
	@echo "Running GoReleaser for $(RELEASE_VERSION)..."
	goreleaser release --clean

release-dry: tag
	@echo "Running GoReleaser dry-run for $(RELEASE_VERSION)..."
	goreleaser release --clean --skip=publish


.PHONY: play

play:
	@echo "Building $(APP_NAME) for linux/amd64..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 \
		go build -ldflags="$(LDFLAGS)" -trimpath \
		-o $(BUILD_DIR)/$(APP_NAME) $(SRC_DIR)

	@echo "Sending binary to $(PLAY_USER)@$(PLAY_HOST):$(PLAY_PATH)..."
	scp $(BUILD_DIR)/$(APP_NAME) \
		$(PLAY_USER)@$(PLAY_HOST):$(PLAY_PATH)/$(APP_NAME)

	@echo "Binary deployed ✔"
