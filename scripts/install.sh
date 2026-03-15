#!/bin/bash
# Agbero - Modern Reverse Proxy & API Gateway
# Install script for Linux and macOS systems
# Usage: curl -fsSL https://agbero.sh | bash
# Or: ./install.sh [--version X.Y.Z] [--dir /usr/local/bin]

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default values
REPO="agberohq/agbero"
INSTALL_DIR="/usr/local/bin"
VERSION="latest"
BINARY_NAME="agbero"

# GitHub API URL
GITHUB_API="https://api.github.com/repos/${REPO}/releases"

# Detect OS and architecture
detect_platform() {
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"

    case "$OS" in
        linux) OS="linux" ;;
        darwin) OS="darwin" ;;
        *)
            echo -e "${RED}Unsupported operating system: $OS${NC}"
            exit 1
            ;;
    esac

    case "$ARCH" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l|armv8l) ARCH="arm64" ;;
        *)
            echo -e "${RED}Unsupported architecture: $ARCH${NC}"
            exit 1
            ;;
    esac

    echo -e "${BLUE}Detected:${NC} $OS/$ARCH"
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --version)
                VERSION="$2"
                shift 2
                ;;
            --dir)
                INSTALL_DIR="$2"
                shift 2
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                show_help
                exit 1
                ;;
        esac
    done
}

# Show help
show_help() {
    cat << EOF
Agbero Installer

Usage: ./install.sh [options]

Options:
    --version VERSION   Install specific version (default: latest)
    --dir DIRECTORY     Installation directory (default: /usr/local/bin)
    --help             Show this help message

Examples:
    curl -fsSL https://agbero.sh | bash
    ./install.sh --version v1.0.0 --dir ~/.local/bin
EOF
}

# Check for required commands
check_dependencies() {
    local missing=()
    
    for cmd in curl tar gunzip; do
        if ! command -v $cmd >/dev/null 2>&1; then
            missing+=($cmd)
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}Missing required dependencies: ${missing[*]}${NC}"
        echo "Please install them and try again."
        exit 1
    fi
}

# Get latest version from GitHub
get_latest_version() {
    if [[ "$VERSION" == "latest" ]]; then
        echo -e "${BLUE}Fetching latest version...${NC}"
        LATEST=$(curl -s "$GITHUB_API/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ -z "$LATEST" ]]; then
            echo -e "${RED}Failed to fetch latest version${NC}"
            exit 1
        fi
        VERSION="$LATEST"
    fi
    echo -e "${GREEN}Version:${NC} $VERSION"
}

# Download and install binary
install_binary() {
    local filename="agbero-${OS}-${ARCH}"
    local archive_ext="tar.gz"
    local download_url="https://github.com/${REPO}/releases/download/${VERSION}/${filename}.${archive_ext}"
    
    echo -e "${BLUE}Downloading Agbero ${VERSION}...${NC}"
    echo -e "URL: $download_url"

    # Create temp directory
    TMP_DIR=$(mktemp -d)
    cd "$TMP_DIR"

    # Download with progress
    if command -v curl >/dev/null 2>&1; then
        curl -L --progress-bar -o "agbero.${archive_ext}" "$download_url"
    else
        wget -q --show-progress -O "agbero.${archive_ext}" "$download_url"
    fi

    # Extract archive
    echo -e "${BLUE}Extracting...${NC}"
    tar -xzf "agbero.${archive_ext}"

    # Make binary executable
    chmod +x agbero

    # Install to target directory
    echo -e "${BLUE}Installing to ${INSTALL_DIR}/agbero...${NC}"
    
    # Check if install directory exists and is writable
    if [[ ! -d "$INSTALL_DIR" ]]; then
        echo -e "${YELLOW}Creating installation directory: ${INSTALL_DIR}${NC}"
        mkdir -p "$INSTALL_DIR"
    fi

    if [[ -w "$INSTALL_DIR" ]]; then
        mv agbero "$INSTALL_DIR/"
    else
        echo -e "${YELLOW}Requesting sudo to install to ${INSTALL_DIR}...${NC}"
        sudo mv agbero "$INSTALL_DIR/"
    fi

    # Cleanup
    cd - > /dev/null
    rm -rf "$TMP_DIR"

    echo -e "${GREEN}✓ Agbero installed successfully!${NC}"
}

# Verify installation
verify_installation() {
    if command -v agbero >/dev/null 2>&1; then
        local installed_path=$(which agbero)
        echo -e "${GREEN}✓ Agbero found in PATH: ${installed_path}${NC}"
        
        # Show version
        local version_output=$(agbero --version 2>/dev/null | head -n1)
        echo -e "${GREEN}✓ ${version_output}${NC}"
    else
        echo -e "${YELLOW}⚠ Agbero not in PATH${NC}"
        echo "Add ${INSTALL_DIR} to your PATH or run:"
        echo "  export PATH=\$PATH:${INSTALL_DIR}"
    fi
}

# Show post-installation instructions
show_next_steps() {
    cat << EOF

${CYAN}═══════════════════════════════════════════════════════════════${NC}
${GREEN}Agbero has been installed successfully!${NC}

${YELLOW}Quick Start:${NC}
  ${BLUE}1. Create a configuration:${NC}        agbero init
  ${BLUE}2. Validate configuration:${NC}        agbero validate
  ${BLUE}3. Run in development mode:${NC}       agbero run --dev
  ${BLUE}4. Serve current directory:${NC}       agbero serve .
  ${BLUE}5. Proxy a local app:${NC}             agbero proxy :3000

${YELLOW}Documentation:${NC}
  • CLI Reference:        https://github.com/${REPO}/blob/main/docs/command.md
  • Installation Guide:   https://github.com/${REPO}/blob/main/docs/install.md
  • Configuration Guide:  https://github.com/${REPO}/blob/main/docs/configuration.md

${YELLOW}Service Installation (requires sudo):${NC}
  ${BLUE}Install as system service:${NC}        sudo agbero service install
  ${BLUE}Start service:${NC}                     sudo agbero service start
  ${BLUE}Check service status:${NC}               sudo agbero service status

${CYAN}═══════════════════════════════════════════════════════════════${NC}
EOF
}

# Main installation flow
main() {
    echo -e "${CYAN}"
    cat << "EOF"

   _____         ___.
  /  _  \    ____\_ |__   ___________  ____
 /  /_\  \  / ___\| __ \_/ __ \_  __ \/  _ \
/    |    \/ /_/  > \_\ \  ___/|  | \(  <_> )
\____|__  /\___  /|___  /\___  >__|   \____/
        \//_____/     \/     \/

 
                                    
EOF
    echo -e "${NC}"
    echo -e "${GREEN}Agbero - Modern Reverse Proxy & API Gateway${NC}"
    echo "=================================================="
    echo ""

    parse_args "$@"
    detect_platform
    check_dependencies
    get_latest_version
    install_binary
    verify_installation
    show_next_steps
}

# Run main function
main "$@"