# Agbero Installation Guide

This guide covers installing Agbero on Linux, macOS, and Windows.

## Installation Methods

Agbero can be installed in several ways:

1. **Install Script** (Linux/macOS) - Quickest method
2. **Direct Download** - Download binaries from GitHub Releases
3. **Build from Source** - For development or custom builds

## Method 1: Install Script (Linux/macOS)

The fastest way to install Agbero is using the install script from GitHub:

```bash
curl -fsSL https://github.com/agberohq/agbero/releases/latest/download/install.sh | bash
```

To install a specific version:

```bash
curl -fsSL https://github.com/agberohq/agbero/releases/download/v1.0.0/install.sh | bash -s -- --version v1.0.0
```

To install to a custom directory:

```bash
curl -fsSL https://github.com/agberohq/agbero/releases/latest/download/install.sh | bash -s -- --dir ~/.local/bin
```

### What the Install Script Does

- Detects your OS and architecture (Linux/macOS, amd64/arm64)
- Downloads the appropriate binary from GitHub Releases
- Extracts and installs it to `/usr/local/bin` (or your specified directory)
- Makes the binary executable
- Provides post-installation instructions

### Install Script Options

| Option | Description |
|--------|-------------|
| `--version VERSION` | Install specific version (e.g., `v1.0.0`) |
| `--dir DIRECTORY` | Installation directory (default: `/usr/local/bin`) |
| `--help` | Show help |

## Method 2: Direct Download from GitHub Releases

Download the appropriate binary for your system from the [releases page](https://github.com/agberohq/agbero/releases/latest).

### Linux

```bash
# x86_64 (AMD64)
curl -LO https://github.com/agberohq/agbero/releases/latest/download/agbero-linux-amd64.tar.gz
tar xzf agbero-linux-amd64.tar.gz
sudo mv agbero /usr/local/bin/

# ARM64
curl -LO https://github.com/agberohq/agbero/releases/latest/download/agbero-linux-arm64.tar.gz
tar xzf agbero-linux-arm64.tar.gz
sudo mv agbero /usr/local/bin/
```

### macOS

```bash
# Intel (AMD64)
curl -LO https://github.com/agberohq/agbero/releases/latest/download/agbero-darwin-amd64.tar.gz
tar xzf agbero-darwin-amd64.tar.gz
sudo mv agbero /usr/local/bin/

# Apple Silicon (ARM64)
curl -LO https://github.com/agberohq/agbero/releases/latest/download/agbero-darwin-arm64.tar.gz
tar xzf agbero-darwin-arm64.tar.gz
sudo mv agbero /usr/local/bin/
```

### Windows

1. Download the appropriate ZIP file:
    - [agbero-windows-amd64.zip](https://github.com/agberohq/agbero/releases/latest/download/agbero-windows-amd64.zip) (64-bit)
    - [agbero-windows-arm64.zip](https://github.com/agberohq/agbero/releases/latest/download/agbero-windows-arm64.zip) (ARM64)

2. Extract the ZIP file

3. Move `agbero.exe` to a directory in your `PATH` (e.g., `C:\Windows\System32` or `C:\Program Files\agbero`)

### Verify Downloads

After downloading, verify the integrity of your download using the checksums:

```bash
# Download checksums
curl -LO https://github.com/agberohq/agbero/releases/latest/download/checksums.txt

# Verify (Linux/macOS)
sha256sum -c checksums.txt --ignore-missing

# Verify (Windows - PowerShell)
Get-FileHash agbero-windows-amd64.zip -Algorithm SHA256
```

## Method 3: Build from Source

### Prerequisites

- Go 1.22 or higher
- Git
- Make (optional)

### Build Steps

```bash
# Clone the repository
git clone https://github.com/agberohq/agbero.git
cd agbero

# Build the binary
go build -o agbero ./cmd/agbero

# Or use make (if available)
make build

# The binary will be in the current directory
# Optionally move to a directory in your PATH
sudo mv agbero /usr/local/bin/
```

## Post-Installation Setup

### 1. Verify Installation

```bash
agbero --version
```

You should see output similar to:
```
agbero version v1.0.0
```

### 2. Initialize Configuration

Run the interactive setup to create your first configuration:

```bash
agbero init
```

This will:
- Create the configuration directory structure
- Generate a secure admin password
- Create a default `agbero.hcl` configuration file
- Set up a local Certificate Authority (for development)

### 3. (Optional) Install CA Support for Firefox

Agbero uses `github.com/smallstep/truststore` for CA management. For Firefox to trust the local CA, you may need to install `nss-tools`:

**Linux (Debian/Ubuntu):**
```bash
sudo apt install libnss3-tools
```

**Linux (RHEL/CentOS/Fedora):**
```bash
sudo yum install nss-tools
# or
sudo dnf install nss-tools
```

**macOS:**
```bash
brew install nss
```

**Windows:**
No additional tools needed - Firefox uses the Windows certificate store.

This is only required if:
- You're using Firefox for local development
- You want Firefox to trust Agbero's locally generated certificates

### 4. Test Your Installation

Run Agbero in development mode:

```bash
agbero run --dev
```

You should see output indicating the server is starting. Press `Ctrl+C` to stop.

## Next Steps

- [**Quick Start**](./index.md) - Learn Agbero basics
- [**CLI Reference**](./command.md) - Complete command documentation
- [**Global Configuration**](./global.md) - Configure the main `agbero.hcl`
- [**Host Configuration**](./host.md) - Define routes and backends

## Troubleshooting

### "agbero: command not found"

The installation directory is not in your `PATH`:

```bash
# Add to PATH temporarily
export PATH=$PATH:/usr/local/bin

# Add to PATH permanently (add to ~/.bashrc, ~/.zshrc, etc.)
echo 'export PATH=$PATH:/usr/local/bin' >> ~/.bashrc
```

### Permission Denied

If you don't have sudo access, install to a user directory:

```bash
# Create a local bin directory
mkdir -p ~/.local/bin

# Install using the script
curl -fsSL https://github.com/agberohq/agbero/releases/latest/download/install.sh | bash -s -- --dir ~/.local/bin

# Add to PATH
export PATH=$PATH:~/.local/bin
```

### Port Conflicts

If ports 80 or 443 are already in use, Agbero will automatically try the next available port. Check what's using the ports:

```bash
# Linux/macOS
sudo lsof -i :80
sudo lsof -i :443

# Windows (PowerShell as Admin)
netstat -ano | findstr :80
netstat -ano | findstr :443
```

### CA Installation Fails

If CA installation fails during `agbero init`:

1. Install the required tools (see "Install CA Support for Firefox" above)
2. Run `agbero init` again

The CA is only needed for local development with HTTPS and does not affect production operation.

### Checksum Verification Failed

If checksum verification fails, the download may be corrupted. Try:

```bash
# Re-download the binary
rm agbero-*.tar.gz
curl -LO https://github.com/agberohq/agbero/releases/latest/download/agbero-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/').tar.gz
```

## Uninstalling Agbero

To remove Agbero:

```bash
# Remove the binary
sudo rm /usr/local/bin/agbero

# Remove configuration (optional)
rm -rf ~/.config/agbero
sudo rm -rf /etc/agbero

# Remove data (optional)
rm -rf ~/.local/share/agbero
sudo rm -rf /var/lib/agbero
```

## Getting Help

- **GitHub Issues**: [https://github.com/agberohq/agbero/issues](https://github.com/agberohq/agbero/issues)
- **Documentation**: [https://github.com/agberohq/agbero/tree/main/docs](https://github.com/agberohq/agbero/tree/main/docs)
```