APP_NAME := agbero
BUILD_DIR := bin
SRC_DIR := ./cmd/agbero

# Remote
PLAY_HOST ?=
PLAY_USER ?= root
PLAY_PATH ?= /usr/local/bin
PLAY_OS   ?= linux
PLAY_ARCH ?= amd64

## UO
REPO_URL = https://github.com/agberohq/agbero-ui
TARGET_DIR = internal/operation/admin
TEMP_DIR = tmp
MINIFY_BIN := $(shell go env GOPATH)/bin/minify

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

# Release version for tagging. CI builds and publishes; this Makefile never does.
RELEASE_VERSION ?=

# Version variables
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# LDFLAGS for version injection
LDFLAGS := -s -w -X "github.com/agberohq/agbero/internal/core/woos.Version=$(VERSION)" \
           -X "github.com/agberohq/agbero/internal/core/woos.Commit=$(COMMIT)" \
           -X "github.com/agberohq/agbero/internal/core/woos.Date=$(DATE)"

.PHONY: all build clean run install build-all version help \
        deps test test-verbose fmt lint tidy changelog dev update-deps \
        ensure-clean ensure-release-version tag release play

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
	@echo "  deploy         - Build locally and atomically deploy via SSH"
	@echo "                   (make deploy PLAY_HOST=host [TEST=1] [YES=1] [MODE=update|install|service])"
	@echo "  version        - Show current version info"
	@echo "  deps           - Install/update dependencies"
	@echo "  test           - Run tests"
	@echo "  test-verbose   - Run tests with verbose output"
	@echo "  fmt            - Format Go code"
	@echo "  lint           - Lint Go code"
	@echo "  tidy           - Tidy go.mod"
	@echo "  changelog      - Generate changelog (requires git-chglog)"
	@echo "  dev            - deps + build then run dev"
	@echo "  update-deps    - Update Go deps"
	@echo ""
	@echo "Release targets:"
	@echo "  ensure-clean   - Fail if repo is dirty"
	@echo "  tag            - Create and push vRELEASE_VERSION at HEAD"
	@echo "  release        - Alias for 'tag' (CI builds and publishes)"
	@echo ""
	@echo "Release usage:"
	@echo "  make release RELEASE_VERSION=0.0.2"
	@echo "  (a tag push triggers GitHub Actions; no local artifact is produced)"

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


# Pull and filter specific assets
ui:
	@echo "Fetching raw assets from $(REPO_URL)..."
	@mkdir -p $(TARGET_DIR) $(TEMP_DIR)
	git clone --depth 1 $(REPO_URL) $(TEMP_DIR)
	rsync -avm --delete --include='*/' --include='*.html' --include='*.css' --include='*.js' --exclude='*' $(TEMP_DIR)/ $(TARGET_DIR)/
	@rm -rf $(TEMP_DIR)
	@echo "Raw UI assets successfully updated in $(TARGET_DIR)"

ui-build: $(MINIFY_BIN)
	@echo "Fetching and minifying assets from $(REPO_URL)..."
	@mkdir -p $(TARGET_DIR) $(TEMP_DIR)
	git clone --depth 1 $(REPO_URL) $(TEMP_DIR)
	@echo "Minifying CSS..."
	@find $(TEMP_DIR) -type f -name "*.css" -exec $(MINIFY_BIN) --type=css -o {} {} \;
	@echo "Minifying JavaScript..."
	@find $(TEMP_DIR) -type f -name "*.js" -exec $(MINIFY_BIN) --type=js -o {} {} \;
	rsync -avm --delete --include='*/' --include='*.html' --include='*.css' --include='*.js' --exclude='*' $(TEMP_DIR)/ $(TARGET_DIR)/
	@rm -rf $(TEMP_DIR)
	@echo "Minified UI assets successfully updated in $(TARGET_DIR)"


# Cross-compile for release targets. Local sanity check only; CI publishes.
build-all: clean
	@echo "Cross-compiling $(APP_NAME) v$(VERSION) for all platforms..."

	@echo "Building for Linux (amd64)..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(APP_NAME)-linux-amd64 $(SRC_DIR)

	@echo "Building for Linux (arm64)..."
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(APP_NAME)-linux-arm64 $(SRC_DIR)

	@echo "Building for Windows (amd64)..."
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(APP_NAME)-windows-amd64.exe $(SRC_DIR)

	@echo "Building for Windows (arm64)..."
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(APP_NAME)-windows-arm64.exe $(SRC_DIR)

	@echo "Building for macOS (Intel)..."
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(APP_NAME)-darwin-amd64 $(SRC_DIR)

	@echo "Building for macOS (Apple Silicon)..."
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(APP_NAME)-darwin-arm64 $(SRC_DIR)

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
# Release helpers (tag-only)
# CI builds, signs, tests, and publishes. Nothing is produced locally.
# --------------------------

ensure-clean:
	@echo "Checking git working tree..."
	@git diff --quiet || (echo "Error: working tree has tracked changes. Commit or stash them."; exit 1)
	@test -z "$$(git status --porcelain)" || (echo "Error: working tree has uncommitted/untracked files:"; git status --porcelain; exit 1)
	@echo "Git working tree is clean"

ensure-release-version:
	@test -n "$(RELEASE_VERSION)" || (echo "Error: set RELEASE_VERSION, e.g. make release RELEASE_VERSION=0.0.2"; exit 1)
	@printf '%s' "$(RELEASE_VERSION)" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$$' \
		|| (echo "Error: RELEASE_VERSION must be semver, e.g. 0.0.2 or 0.1.0-rc.1"; exit 1)

tag: ensure-clean ensure-release-version
	@test "$$(git rev-parse --abbrev-ref HEAD)" = "main" \
		|| (echo "Error: release from main (current: $$(git rev-parse --abbrev-ref HEAD))"; exit 1)
	@if git rev-parse -q --verify "refs/tags/v$(RELEASE_VERSION)" >/dev/null; then \
		echo "Error: tag v$(RELEASE_VERSION) already exists. Re-run CI instead of moving it."; \
		exit 1; \
	fi
	@echo "Creating tag v$(RELEASE_VERSION) at HEAD $$(git rev-parse --short HEAD)"
	@git tag -a "v$(RELEASE_VERSION)" -m "v$(RELEASE_VERSION)"
	@git push $(REMOTE) "v$(RELEASE_VERSION)" || { \
		echo "Error: failed to push the tag; removing the local tag so you can retry"; \
		git tag -d "v$(RELEASE_VERSION)" >/dev/null; \
		exit 1; \
	}

release: tag
	@echo "Pushed v$(RELEASE_VERSION). GitHub Actions builds and publishes; nothing was built locally."


.PHONY: deploy

# Safe operator deployment. Build/version/service/health/rollback logic lives in
# tools/deployer so this target stays readable. TEST=1 runs tests first.
deploy:
	@go run ./tools/deployer \
		--host "$(PLAY_HOST)" \
		--user "$(PLAY_USER)" \
		--mode "$(or $(MODE),auto)" \
		$(if $(filter 1,$(TEST)),--test) \
		$(if $(filter 1,$(YES)),--yes) \
		$(DEPLOY_ARGS)

.PHONY: play

# Deprecated alias for the safe deployer.
play: deploy
