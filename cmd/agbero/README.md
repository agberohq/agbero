# Agbero CLI Reference

Agbero is a modern reverse proxy, load balancer, and API gateway written in Go. It supports HTTP/HTTPS proxying, TCP proxying, static file serving, firewall rules, rate limiting, Let's Encrypt integration, clustering via gossip protocol, and more. Configurations are written in HCL format for simplicity and readability.

This README provides complete documentation for the Agbero command-line interface (CLI).

## Installation

### From Binary Release
Download the latest release from the repository and install it manually.

For Linux/macOS:
```bash
curl -L https://git.imaxinacion.net/aibox/agbero/releases/latest/download/agbero-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m) -o agbero
chmod +x agbero
sudo mv agbero /usr/local/bin/

# Verify installation
agbero --version
```

For Windows:
Download the executable from the releases page and add it to your PATH.

### From Source
```bash
go install git.imaxinacion.net/aibox/agbero/cmd/agbero@latest
```

## Global Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-c, --config` | Path to configuration file (`.hcl`) | Auto-detected (see Configuration Discovery Order) |
| `-d, --dev` | Enable development mode (detailed logs, staging certificates) | `false` |
| `--version` | Show version information | N/A |
| `--help` | Show help | N/A |

## Commands Overview

Agbero supports a variety of commands for running, managing, and configuring the proxy.

### 🚀 `run` - Run in foreground
Run Agbero interactively, ideal for development or testing.

**Usage:**
```bash
agbero run [flags]
```

**Flags:**
- `--dev`: Enable development mode
- `--gossip`: Enable gossip clustering (overrides config if set)

**Examples:**
```bash
# Run with auto-detected config
agbero run

# Run with custom config and dev mode
agbero run --config ./agbero.hcl --dev

# Run with gossip enabled
agbero run --config ./cluster.hcl --gossip
```

**Behavior:**
- Loads and validates configuration.
- Starts HTTP/HTTPS listeners based on `bind` settings.
- Watches for host configuration changes in `hosts_dir`.
- Supports hot reload via SIGHUP signal.
- In dev mode: Enables debug logging and uses Let's Encrypt staging.

**Exit codes:**
- `0`: Graceful shutdown
- `1`: Error (e.g., config invalid)

### 🔧 `install` - Scaffold configuration and install as system service
Generates a default configuration and optionally installs Agbero as a background service.

**Usage:**
```bash
agbero install [flags]
```

**Flags:**
- `--here`: Install configuration in the current directory (skips service installation)

**Examples:**
```bash
# System-wide installation (requires sudo on Linux/macOS)
sudo agbero install

# User-local installation (no sudo)
agbero install --here

# Custom config path (service install)
sudo agbero install --config /etc/agbero/agbero.hcl
```

**Behavior:**
- Generates `agbero.hcl` with placeholders for secrets.
- Creates directories: `hosts.d`, `certs`, `data`, `logs`.
- Adds default host configs (`admin.hcl`, `web.hcl`).
- If not `--here`, installs as a system service (systemd on Linux, launchd on macOS, Windows Service on Windows).
- Service runs as root (system) or current user (`--here`).

**Supported Platforms:**
- Linux: systemd
- macOS: launchd
- Windows: Windows Services

### ⚡ `start` / `stop` - Service control
Control the installed Agbero service.

**Usage:**
```bash
agbero start [flags]
agbero stop [flags]
```

**Examples:**
```bash
# Start system service
sudo agbero start --config /etc/agbero/agbero.hcl

# Stop user service
agbero stop --config ~/.config/agbero/agbero.hcl
```

**Behavior:**
- Requires the same `--config` as used in `install`.
- On Linux/macOS, may require sudo for system services.

Note: There is no explicit `restart` command; use `stop` followed by `start`, or `reload` for hot reload.

### 🗑️ `uninstall` - Remove service
Uninstall the Agbero service (configuration files are preserved).

**Usage:**
```bash
agbero uninstall [flags]
```

**Examples:**
```bash
# Uninstall system service
sudo agbero uninstall --config /etc/agbero/agbero.hcl
```

**Behavior:**
- Stops the service if running.
- Removes service definitions (e.g., systemd unit, launchd plist).

### 🔄 `reload` - Hot reload configuration
Sends SIGHUP to the running process to reload hosts without restart.

**Usage:**
```bash
agbero reload [flags]
```

**Examples:**
```bash
# Reload system service
sudo agbero reload --config /etc/agbero/agbero.hcl
```

**Behavior:**
- Reads PID from `data_dir/agbero.pid`.
- Triggers reload of host configurations.

### ✅ `validate` - Validate configuration
Checks the main config and all host files for syntax and validity.

**Usage:**
```bash
agbero validate [flags]
```

**Examples:**
```bash
agbero validate --config ./agbero.hcl
```

**Output Example:**
```
INFO configuration is valid hosts_count=5 hosts_dir=/etc/agbero/hosts.d
```

### 📋 `hosts` - List configured hosts
Lists all loaded host configurations from `hosts_dir`.

**Usage:**
```bash
agbero hosts [flags]
```

**Examples:**
```bash
agbero hosts --config ./agbero.hcl
```

**Output Example:**
```
INFO configured host host_id=admin domains=[admin.localhost] routes=1
INFO configured host host_id=cockroach domains=[cockroach.localhost] routes=1
```

### 🔐 `hash` - Generate bcrypt hash
Generates a bcrypt hash for passwords (used in `basic_auth`).

**Usage:**
```bash
agbero hash [flags]
```

**Flags:**
- `-p, --password`: Password to hash (interactive if omitted)

**Examples:**
```bash
# Interactive
agbero hash

# Direct
agbero hash --password "mysecret"
```

**Output Example:**
```
$2a$10$...
```

### 🌐 `serve` - Ephemeral static file server
Serve a directory instantly (no persistent config).

**Usage:**
```bash
agbero serve [path] [flags]
```

**Flags:**
- `-p, --port`: Listen port (default: 8000)
- `-b, --bind`: Bind address (default: localhost)
- `-s, --https`: Enable HTTPS (auto-generates cert)

**Examples:**
```bash
# Serve current directory on port 8000
agbero serve

# Serve specific path with HTTPS
agbero serve /var/www --port 8443 --https
```

### 🔀 `proxy` - Ephemeral reverse proxy
Proxy a local target instantly (no persistent config).

**Usage:**
```bash
agbero proxy <target> [domain] [flags]
```

**Flags:**
- `-p, --port`: Listen port (default: 8080)
- `-b, --bind`: Bind address (default: localhost)
- `-s, --https`: Enable HTTPS

**Examples:**
```bash
# Proxy localhost:3000 as localhost:8080
agbero proxy :3000

# Proxy with domain and HTTPS
agbero proxy http://127.0.0.1:3000 app.localhost --https
```

### 🛣️ `route` - Manage routes interactively
Add or remove host configurations using interactive prompts.

**Subcommands:**
- `route add`: Add a new route (proxy, static, or TCP)
- `route remove`: Remove an existing route file

**Usage:**
```bash
agbero route add [flags]
agbero route remove [flags]
```

**Examples:**
```bash
# Add a new route
agbero route add --config ./agbero.hcl

# Remove a route
agbero route remove --config ./agbero.hcl
```

**Behavior:**
- Uses interactive forms to collect domain, target, etc.
- Writes `.hcl` files to `hosts_dir`.
- Supports reverse proxy, static sites, TCP proxies.

## Gossip Commands
Manage clustering with Serf gossip protocol.

### 🔄 `gossip init` - Initialize gossip
Generate private key and display config snippet.

**Usage:**
```bash
agbero gossip init [flags]
```

**Examples:**
```bash
agbero gossip init --config ./agbero.hcl
```

### 🎫 `gossip token` - Generate service token
Create a JWT for dynamic service registration.

**Usage:**
```bash
agbero gossip token [flags]
```

**Flags:**
- `-s, --service`: Service name (required)
- `-t, --ttl`: Token duration (default: 720h)

**Examples:**
```bash
agbero gossip token --service my-app --ttl 24h --config ./agbero.hcl
```

### 🔑 `gossip secret` - Generate encryption secret
Generate a base64-encoded AES key for gossip encryption.

**Usage:**
```bash
agbero gossip secret
```

### 📊 `gossip status` - Show gossip status
Display gossip configuration and key status.

**Usage:**
```bash
agbero gossip status [flags]
```

**Examples:**
```bash
agbero gossip status --config ./agbero.hcl
```

## Certificate Commands
Manage TLS certificates (using mkcert or similar).

### 📜 `cert install` - Install CA root
Install self-signed CA to system trust store.

**Usage:**
```bash
agbero cert install [flags]
```

**Flags:**
- `-f, --force`: Force reinstall

### 🗑️ `cert uninstall` - Uninstall CA
Remove CA from trust store and delete files.

**Usage:**
```bash
agbero cert uninstall
```

### 📋 `cert list` - List certificates
List all certificates in `certs_dir`.

**Usage:**
```bash
agbero cert list [flags]
```

### ℹ️ `cert info` - Show cert directory info
Display certificate storage details.

**Usage:**
```bash
agbero cert info [flags]
```

**Flags:**
- `-d, --dir`: Override directory

## Key Management Commands
Manage Ed25519 keys for gossip auth.

### 🔑 `key init` - Generate private key
Create a new key file.

**Usage:**
```bash
agbero key init [flags]
```

### 🎫 `key gen` - Generate token
Create a JWT using the private key.

**Usage:**
```bash
agbero key gen [flags]
```

**Flags:**
- `-s, --service`: Service name
- `-t, --ttl`: Duration

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AGBERO_CONTAINER` | Detect container environment | `false` |
| `KUBERNETES_SERVICE_HOST` | Kubernetes detection | N/A |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | General error (details logged) |

## Configuration Discovery Order
Without `--config`:

1. Environment `AGBERO_CONFIG`
2. Current dir `./agbero.hcl`
3. User dir `~/.config/agbero/agbero.hcl`
4. System dir `/etc/agbero/agbero.hcl`

## Examples

### Development Setup
```bash
# Install config locally
agbero install --here

# Run in foreground
agbero run --dev

# Add a route
agbero route add
```

### Production Cluster
```bash
# Install system-wide
sudo agbero install

# Init gossip
sudo agbero gossip init

# Generate secret
agbero gossip secret

# Update config with gossip block

# Start service
sudo agbero start

# Generate token for a service
agbero gossip token --service app1
```

## Troubleshooting

- **Config not found:** Use `--config` or run `install`.
- **Service errors:** Check logs in `logs_dir/agbero.log`.
- **Port conflicts:** Use `netstat` or `lsof` to check ports.
- **CA install fails:** Run with sudo; check trust store.
- **Reload not working:** Ensure `data_dir` is set and PID file exists.

## Tips & Best Practices

- Use `--dev` for local testing.
- Secure secrets: Replace placeholders in generated config.
- Monitor: Integrate with VictoriaLogs for advanced logging.
- Clustering: Use gossip for dynamic service discovery.
- Firewall: Configure rules in `security.firewall` for protection.
- Rate Limits: Define global and per-route limits.
- Auto-reload: Edit host files; changes apply without restart.
- Ephemeral mode: Use `serve`/`proxy` for quick tests.

For full config reference, see the embedded `data/agbero.hcl` template.