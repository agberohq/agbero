# Agbero CLI Reference

Agbero is a modern reverse proxy, load balancer, and API gateway written in Go. It supports HTTP/HTTPS proxying, TCP proxying, static file serving, firewall rules, rate limiting, Let's Encrypt integration, clustering via gossip protocol, and more. Configurations are written in HCL format for simplicity and readability.

This document provides complete documentation for the Agbero command-line interface (CLI).

> **Installation Guide**  
> For installation instructions, see the [Installation Guide](./install.md).

## Global Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-c, --config` | Path to configuration file (`.hcl`) | Auto-detected (see Configuration Discovery Order) |
| `-d, --dev` | Enable development mode (detailed logs, staging certificates) | `false` |
| `--version` | Show version information | N/A |
| `--help` | Show help | N/A |

## Commands

### `home` - Navigate configuration directories
Print or navigate to Agbero configuration directories.

**Usage:**
```bash
agbero home [target] [action]
```

**Arguments:**
- `target`: Directory to locate (`hosts`, `certs`, `data`, `logs`, `work`, `config`, or omit for root)
- `action`: `@` to open shell, `@cat` to view file, `@vim`/`@nano`/`@code` to edit

**Examples:**
```bash
# Show root directory path
agbero home

# Open shell in root directory
agbero home @

# Show config file path
agbero home config

# View config file contents
agbero home config @cat

# Edit config with vim
agbero home config @vim

# Navigate to hosts directory
cd $(agbero home hosts)
agbero home hosts @
```

**Available targets:** `hosts`, `certs`, `data`, `logs`, `work`, `config`

### `run` - Run in foreground
Run Agbero interactively, ideal for development or testing.

**Usage:**
```bash
agbero run [flags]
```

**Flags:**
- `--dev`: Enable development mode

**Examples:**
```bash
# Run with auto-detected config
agbero run

# Run with custom config and dev mode
agbero run --config ./agbero.hcl --dev
```

**Behavior:**
- Loads and validates configuration.
- Starts HTTP/HTTPS listeners based on `bind` settings.
- Watches for host configuration changes in `hosts_dir`.
- Supports hot reload via SIGHUP signal.

### `service` - Service management
Manage Agbero as a system service.

**Subcommands:**
- `install` - Install configuration and system service
- `uninstall` - Uninstall system service
- `start` - Start system service
- `stop` - Stop system service

**Usage:**
```bash
agbero service <subcommand> [flags]
```

**Flags for install:**
- `--here`: Install configuration in current directory (skip service install)

**Examples:**
```bash
# Install system-wide
sudo agbero service install

# Install locally (no service)
agbero service install --here

# Start service
sudo agbero service start

# Stop service
sudo agbero service stop

# Uninstall service
sudo agbero service uninstall
```

### `reload` - Hot reload configuration
Sends SIGHUP to the running process to reload hosts without restart.

**Usage:**
```bash
agbero reload [flags]
```

**Examples:**
```bash
# Reload system service
sudo agbero reload
```

### `validate` - Validate configuration
Checks the main config and all host files for syntax and validity.

**Usage:**
```bash
agbero validate [flags]
```

**Examples:**
```bash
agbero validate --config ./agbero.hcl
```

### `hosts` - List configured hosts
Lists all loaded host configurations from `hosts_dir`.

**Usage:**
```bash
agbero hosts [flags]
```

**Examples:**
```bash
agbero hosts --config ./agbero.hcl
```

### `init` - Interactive setup
Run the interactive setup wizard to create configuration.

**Usage:**
```bash
agbero init
```

### `hash` - Generate bcrypt hash
Generates a bcrypt hash for passwords (used in `basic_auth`).

**Usage:**
```bash
agbero hash [flags]
```

**Flags:**
- `-p, --password`: Password to hash (interactive if omitted)

**Examples:**
```bash
agbero hash --password "mysecret"
```

### `serve` - Ephemeral static file server
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
# Serve current directory
agbero serve

# Serve with HTTPS
agbero serve /var/www --https
```

### `proxy` - Ephemeral reverse proxy
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
# Proxy localhost:3000
agbero proxy :3000

# Proxy with domain and HTTPS
agbero proxy http://127.0.0.1:3000 app.localhost --https
```

### `route` - Manage routes interactively
Add or remove host configurations using interactive prompts.

**Subcommands:**
- `add` - Add a new route
- `remove` - Remove an existing route

**Usage:**
```bash
agbero route add [flags]
agbero route remove [flags]
```

**Examples:**
```bash
# Add a new route
agbero route add

# Remove a route
agbero route remove
```

### `cert` - Certificate management
Manage TLS certificates.

**Subcommands:**
- `install` - Install CA certificate
- `uninstall` - Uninstall CA certificate
- `list` - List certificates
- `info` - Show certificate info

**Usage:**
```bash
agbero cert <subcommand> [flags]
```

**Flags:**
- `-f, --force`: Force reinstall (for install)
- `-d, --dir`: Override directory (for info)

**Examples:**
```bash
# Install CA
agbero cert install

# List certificates
agbero cert list

# Show certificate info
agbero cert info
```

### `key` - Key management
Manage API authentication keys.

**Subcommands:**
- `init` - Generate master private key
- `gen` - Generate auth token for service

**Usage:**
```bash
agbero key <subcommand> [flags]
```

**Flags for gen:**
- `-s, --service`: Service name (required)
- `-t, --ttl`: Token validity duration

**Examples:**
```bash
# Initialize master key
agbero key init

# Generate token for service
agbero key gen --service myapp --ttl 24h
```

### `cluster` - Cluster management
Manage cluster settings.

**Subcommands:**
- `secret` - Generate encryption secret
- `start` - Start as cluster seed node
- `join` - Join existing cluster

**Usage:**
```bash
agbero cluster <subcommand> [flags]
```

**Examples:**
```bash
# Generate cluster secret
agbero cluster secret

# Join cluster
agbero cluster join 192.168.1.10 --secret b64.abc123
```

### `help` - Show help examples
Display usage examples.

**Usage:**
```bash
agbero help
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `AGBERO_CONTAINER` | Detect container environment |
| `KUBERNETES_SERVICE_HOST` | Kubernetes detection |

## Configuration Discovery Order
Without `--config`:

1. Current directory `./agbero.hcl`
2. User directory `~/.config/agbero/agbero.hcl`
3. System directory `/etc/agbero/agbero.hcl`

## Examples

### Development Setup
```bash
# Install config locally
agbero service install --here

# Run in foreground
agbero run --dev

# Add a route
agbero route add
```

### Production Setup
```bash
# Install system-wide
sudo agbero service install

# Start service
sudo agbero service start

# Generate cluster secret
agbero cluster secret

# Generate API token
agbero key gen --service app1
```

## Troubleshooting

- **Config not found:** Use `--config` or run `service install --here`
- **Service errors:** Check logs in `logs_dir/agbero.log`
- **Reload not working:** Ensure `data_dir` is set and PID file exists
