APP_NAME := agbero
BUILD_DIR := bin
SRC_DIR := ./cmd/agbero

.PHONY: all build clean run install-deps build-all

all: build

# Install dependencies
deps:
	go mod download
	go mod tidy

# Build for current OS
build:
	@echo "Building $(APP_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build -ldflags="-s -w" -o $(BUILD_DIR)/$(APP_NAME) $(SRC_DIR)
	@echo "Done! Binary is in $(BUILD_DIR)/$(APP_NAME)"

# Run interactively (Development helper)
run:
	go run $(SRC_DIR) run --dev --config ./etc/agbero/config.hcl

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)

# Cross-compile for release
build-all: clean
	@echo "Building for Linux (amd64)..."
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(APP_NAME)-linux-amd64 $(SRC_DIR)

	@echo "Building for Linux (arm64)..."
	GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(APP_NAME)-linux-arm64 $(SRC_DIR)

	@echo "Building for Windows..."
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(APP_NAME)-windows-amd64.exe $(SRC_DIR)

	@echo "Building for macOS (Intel)..."
	GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(APP_NAME)-darwin-amd64 $(SRC_DIR)

	@echo "Building for macOS (Apple Silicon)..."
	GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(APP_NAME)-darwin-arm64 $(SRC_DIR)