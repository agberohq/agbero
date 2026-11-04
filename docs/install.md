# Installing Agbero

Agbero is distributed as a single binary with no external dependencies. This guide covers installation on Linux, macOS, and Windows.

## Quick Install (Linux/macOS)


**Edge (development)**
```bash
curl -fsSL https://raw.githubusercontent.com/agberohq/agbero/refs/heads/main/scripts/install.sh | bash
```
**Release (stable)**
```bash
curl -fsSL https://github.com/agberohq/agbero/releases/latest/download/install.sh | bash
```

The installer verifies the release archive against `checksums.txt` before installing. Useful flags:

```bash
# Verify the download without installing
curl -fsSL .../install.sh | bash -s -- --check

# Pin a release and install into your user bin directory
curl -fsSL .../install.sh | bash -s -- --version v0.1.4 --user

# System install (root)
curl -fsSL .../install.sh | sudo bash -s -- --system --version v0.1.4

# Air-gapped / local assets
./install.sh --from-file ./dist/release --version v0.1.4
```

## Manual Installation

### Linux (amd64/arm64)

```bash
# Download the latest release
curl -LO https://github.com/agberohq/agbero/releases/latest/download/agbero-linux-amd64.tar.gz

# Extract
tar xzf agbero-linux-amd64.tar.gz

# Install to /usr/local/bin
sudo mv agbero /usr/local/bin/
sudo chmod +x /usr/local/bin/agbero

# Verify installation
agbero --version
```

### macOS (Intel/Apple Silicon)

```bash
# Download the latest release
curl -LO https://github.com/agberohq/agbero/releases/latest/download/agbero-darwin-amd64.tar.gz

# Extract
tar xzf agbero-darwin-amd64.tar.gz

# Install to /usr/local/bin
sudo mv agbero /usr/local/bin/
sudo chmod +x /usr/local/bin/agbero

# Verify installation
agbero --version
```

### Windows

1. Download the latest Windows binary from the [releases page](https://github.com/agberohq/agbero/releases/latest)
2. Extract `agbero.exe` to a directory in your PATH (e.g., `C:\Windows\System32\`)
3. Open Command Prompt or PowerShell and verify:
   ```powershell
   agbero --version
   ```

## Post-Installation Setup

### 1. Initialize Configuration

After installing, create your initial configuration:

```bash
# Interactive setup wizard
agbero init
```

This will:
- Create the directory structure (`hosts.d`, `certs.d`, `data.d`, `logs.d`, `work.d`)
- Generate a secure admin password
- Create an internal authentication key
- Set up a local Certificate Authority (for development)
- Write a default `agbero.hcl` configuration file

### 2. Install Local CA (Optional, for development)

For local HTTPS development, install the Certificate Authority:

```bash
# Install the CA to your system trust store
sudo agbero cert install
```

This enables browsers to trust certificates issued by Agbero for `*.localhost` domains.

### 3. Install as a System Service (Production)

For production deployments, install Agbero as a system service. **Run `init` as root for a system install** so the config and keeper live in `/etc/agbero` and `/var/lib/agbero`, not in your user profile:

```bash
# System-wide init (requires sudo)
sudo agbero init

# Install and start the service
sudo agbero service install
sudo agbero service start

# Check status
sudo agbero service status
```

If you already ran `agbero init` as a normal user, the service install will not see that config. Either re-run `sudo agbero init` (system tree) or keep using the user tree with `agbero run`; do not maintain two config trees. (`agbero service install --user` is not supported yet.)

`agbero init` writes a `0600` passphrase file and points `keeper.passphrase_file` at it, so the service can unlock the keeper without an environment variable.

## Verifying Installation

Run these commands to verify everything is working:

```bash
# Check version
agbero --version

# Validate default configuration
agbero config validate

# Start in development mode
agbero run --dev
```

Then open https://localhost in your browser. You should see the Agbero welcome page.

## Directory Structure

After installation and initialization, Agbero creates this structure:

```
/etc/agbero/                  # System-wide (or ~/.config/agbero/ for user)
├── agbero.hcl                # Main configuration
├── hosts.d/                  # Host-specific route files
│   ├── admin.hcl
│   └── web.hcl
├── certs.d/                  # TLS certificates
│   ├── ca-cert.pem
│   └── localhost-443-cert.pem
├── data.d/                   # Runtime data
│   ├── firewall.db
│   └── agbero.pid
├── logs.d/                   # Log files
│   └── agbero.log
└── work.d/                   # Working directory (Git deployments)
```

## Uninstalling

### Remove everything (service, CA, configurations, data, binary)

```bash
# Complete uninstall with confirmation
sudo agbero uninstall

# Skip confirmation
sudo agbero uninstall --force
```

### Remove only the service

```bash
sudo agbero service uninstall
```

### Remove only the CA

```bash
sudo agbero cert uninstall
```

## Next Steps

- **Quick Start**: Run `agbero run --dev` and visit https://localhost
- **CLI Reference**: See the [Command Guide](./command.md) for all available commands
- **Configuration**: Learn about [Global Configuration](./global.md) and [Host Configuration](./host.md)
- **Serverless**: Learn about [REST proxying and workers](./serverless.md)

## Platform-Specific Notes

### Linux
- Systemd is used for service management
- Configuration lives in `/etc/agbero/` when installed as root
- User installations use `~/.config/agbero/`

### macOS
- Launchd is used for service management
- System-wide config: `/etc/agbero/`
- User config: `~/Library/Application Support/agbero/`

### Windows
- Windows Service API is used for service management
- System-wide config: `%ProgramData%\agbero\`
- User config: `%AppData%\agbero\`
- Run PowerShell/Command Prompt as Administrator for service commands

## Troubleshooting Installation

### "command not found"
- Ensure the binary is in your PATH
- Try reinstalling or using the full path: `/usr/local/bin/agbero`

### Permission denied
- Use `sudo` for system-wide installation
- For user installation, use `~/.local/bin/` or similar

### Port binding errors
- Ports 80 and 443 require root/admin privileges
- Use higher ports (>1024) for non-root testing
- On Linux, you can use `setcap` to allow binding without root

### CA installation fails
- Ensure you have admin/sudo privileges
- On Linux, you may need to install  `nss` or `libnss3-tools` for Firefox support
- Run with `--force` to retry

## Documentation Guide

Navigate through the documentation to master Agbero:

- [**Home**](./index.md) - Introduction to Agbero.
- [**Command Line**](./command.md) - Using Agbero from the command line.
- [**Global Config**](./global.md) - Configure bind addresses, TLS, logging, rate limits, and clustering.
- [**Host Config**](./host.md) - Define routes, backends, auth, and TLS per virtual host.
- [**Serverless Guide**](./serverless.md) - REST proxying, workers, and scheduled tasks without the cloud.
- [**Advanced Guide**](./advance.md) - Deep dive into Clustering, Git Deployments, and Firewall tuning.
- [**Plugin Guide**](./plugin.md) - Write custom high-performance middleware using WebAssembly.
- [**API Reference**](./api.md) - Dynamic route management via the cluster API.
- [**Contributor Guide**](./contributor.md) - Architecture overview and guidelines for contributing to Agbero.
## First Run — Keeper Initialisation

On the very first `agbero run`, if no keeper database exists at `data.d/keeper.db`, Agbero walks you through creating one interactively. Here is what that looks like in your terminal:

```
$ agbero run
[INFO] No keeper database found — creating a new one.

Enter master passphrase: ████████
Confirm master passphrase: ████████

[INFO] Keeper created and unlocked.
[INFO] Admin user setup...
Admin username: admin
Admin password: ████████

[INFO] Internal Ed25519 auth key generated and stored in keeper.
[INFO] Agbero is ready — listening on :80 and :443
```

For non-interactive environments (system service, Docker, CI), use a passphrase file or the canonical environment variable so Agbero can unlock without prompting. `agbero init` writes a `0600` passphrase file next to the config and points `keeper.passphrase_file` at it:

```bash
AGBERO_KEEPER_PASSPHRASE=mypassphrase agbero run
# or, preferred for services:
# keeper { passphrase_file = "/etc/agbero/keeper.passphrase" }
```

> **Important:** The keeper database (`data.d/keeper.db`) is encrypted at rest. Without the correct passphrase, Agbero cannot start. Store your passphrase securely — in a secrets manager, a `.env` file outside version control, or your system's service environment. If you lose the passphrase, you lose all stored secrets.
