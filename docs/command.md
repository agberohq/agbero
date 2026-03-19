# Agbero Command Line Interface

Complete reference for all Agbero commands and subcommands based on the actual implementation in `cmd/agbero/main.go`.

## Global Flags

| Flag | Description |
|------|-------------|
| `-c, --config string` | Path to configuration file |
| `--version` | Show version information |
| `--help` | Show help |

## Core Commands

### `init` - Scaffold Configuration
Initialize a new configuration in the current directory.

**Usage:**
```bash
agbero init
```

**Description:**
Creates the directory structure (`hosts.d`, `certs.d`, `data.d`, `logs.d`, `work.d`) and a default `agbero.hcl` configuration file.

---

### `run` - Run Agbero
Start Agbero using the discovered configuration.

**Usage:**
```bash
agbero run [flags]
```

**Flags:**
- `-d, --dev`: Enable development mode (debug logs, staging certificates)

**Examples:**
```bash
agbero run
agbero run --dev
agbero run --config ./custom/agbero.hcl
```

---

## Configuration Commands

### `config` - Configuration Management

**Subcommands:**

| Command | Description |
|---------|-------------|
| `config validate` | Validate configuration file |
| `config reload` | Hot-reload the running instance (SIGHUP) |
| `config view` | Print configuration file |
| `config path` | Show resolved config file path |
| `config edit` | Open configuration in $EDITOR |

**Usage:**
```bash
agbero config <subcommand> [flags]
```

**Flags for view:**
- `-e, --editor string`: Open in specific editor (vim, nano, cat, etc.)

**Examples:**
```bash
# Validate configuration
agbero config validate

# Reload running instance
sudo agbero config reload

# View configuration
agbero config view
agbero config view --editor vim

# Show config path
agbero config path

# Edit configuration
agbero config edit
```

---

## Secret Management

### `secret` - Generate Secrets and Keys

**Subcommands:**

| Command | Description |
|---------|-------------|
| `secret cluster` | Generate AES-256 gossip secret key |
| `secret key init` | Generate master private key for internal auth |
| `secret token` | Generate signed API token for a service |
| `secret hash` | Generate bcrypt hash of a password |
| `secret password` | Generate random password and its bcrypt hash |

**Usage:**
```bash
agbero secret <subcommand> [flags]
```

**Flags for token:**
- `-s, --service string`: Service identifier (required)
- `-t, --ttl duration`: Token validity duration (default: 8760h)

**Flags for hash:**
- `-p, --password string`: Password to hash (prompts if omitted)

**Arguments for password:**
- `length`: Password length (default: 32)

**Examples:**
```bash
# Generate cluster secret
agbero secret cluster

# Initialize auth key
agbero secret key init

# Generate API token
agbero secret token --service myapp --ttl 24h

# Generate password hash
agbero secret hash --password "mysecret"

# Generate random password
agbero secret password
agbero secret password 16
```

---

## Host Management

### `host` - Manage Hosts and Routes

**Subcommands:**

| Command | Description |
|---------|-------------|
| `host list` | List all configured hosts |
| `host add` | Add a new host/route (interactive) |
| `host remove` | Remove a host/route (interactive) |

**Usage:**
```bash
agbero host <subcommand> [flags]
```

**Template files used:**
- `proxy.hcl` - Reverse proxy route template
- `static.hcl` - Static site route template
- `tcp.hcl` - TCP proxy route template

**Examples:**
```bash
# List hosts
agbero host list

# Add a new route (interactive)
agbero host add

# Remove a route (interactive)
agbero host remove
```

---

## Certificate Management

### `cert` - Manage TLS Certificates

**Subcommands:**

| Command | Description |
|---------|-------------|
| `cert install` | Install CA certificate |
| `cert uninstall` | Uninstall CA certificate |
| `cert list` | List managed certificates |
| `cert info` | Show certificate store information |

**Usage:**
```bash
agbero cert <subcommand> [flags]
```

**Flags for install:**
- `-f, --force`: Force reinstall even if already installed

**Flags for info:**
- `-d, --dir string`: Override certificate directory

**Examples:**
```bash
# Install CA
agbero cert install
agbero cert install --force

# Uninstall CA
agbero cert uninstall

# List certificates
agbero cert list

# Show certificate info
agbero cert info
```

---

## Service Management

### `service` - Manage System Service

**Subcommands:**

| Command | Description |
|---------|-------------|
| `service install` | Install configuration and system service |
| `service uninstall` | Uninstall system service |
| `service start` | Start system service |
| `service stop` | Stop system service |
| `service restart` | Restart system service |
| `service status` | Check service status |

**Usage:**
```bash
agbero service <subcommand> [flags]
```

**Flags for install:**
- `--here`: Install configuration in current directory only (skip service)

**Flags for uninstall:**
- `--all`: Remove service, CA, all data, and binary
- `--force`: Skip confirmation prompt

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

# Restart service
sudo agbero service restart

# Check status
sudo agbero service status

# Uninstall service only
sudo agbero service uninstall

# Uninstall everything
sudo agbero service uninstall --all
sudo agbero service uninstall --all --force
```

---

## Cluster Management

### `cluster` - Manage Cluster Settings

**Subcommands:**

| Command | Description |
|---------|-------------|
| `cluster start` | Start as cluster seed node |
| `cluster join` | Join an existing cluster |

**Usage:**
```bash
agbero cluster <subcommand> [flags]
```

**Arguments for join:**
- `ip`: IP address of the cluster seed node (positional argument)

**Flags:**
- `-s, --secret string`: Cluster secret key

**Examples:**
```bash
# Start as seed node
agbero cluster start --config ./seed.hcl

# Join cluster
agbero cluster join 192.168.1.10 --secret b64.encoded-key
```

---

## Uninstall

### `uninstall` - Complete Uninstall
Alias for `service uninstall --all`. Removes everything Agbero installed.

**Usage:**
```bash
agbero uninstall [flags]
```

**Flags:**
- `--force`: Skip confirmation prompt

**Examples:**
```bash
sudo agbero uninstall
sudo agbero uninstall --force
```

---

## Navigation

### `home` - Navigate Configuration Directories
Print or navigate to Agbero configuration directories.

**Usage:**
```bash
agbero home [target] [action]
```

**Arguments:**
- `target`: Directory to locate:
  - `hosts` - Hosts directory (`hosts.d`)
  - `certs` - Certificates directory (`certs.d`)
  - `data` - Data directory (`data.d`)
  - `logs` - Logs directory (`logs.d`)
  - `work` - Work directory (`work.d`)
  - `config` - Configuration file
  - (omit) - Root Agbero directory
- `action`: Action to perform:
  - `@` - Open shell in the directory
  - `@editor` - View/edit file (e.g., `@cat`, `@vim`, `@nano`, `@code`)
  - `.` or `open` - Open in file explorer
  - (omit) - Print the path

**Examples:**
```bash
# Show root directory path
agbero home

# Open shell in root directory
agbero home @

# Open root directory in file explorer
agbero home .

# Show config file path
agbero home config

# View config file contents
agbero home config @cat

# Edit config with vim
agbero home config @vim

# Open hosts directory in file explorer
agbero home hosts .

# Open shell in certs directory
agbero home certs @

# Navigate to logs directory
cd $(agbero home logs)
```

**Available targets:** `hosts`, `certs`, `data`, `logs`, `work`, `config`

---

## Ephemeral Commands

### `serve` - Static File Server
Serve a static directory instantly without persistent configuration.

**Usage:**
```bash
agbero serve [path] [flags]
```

**Arguments:**
- `path`: Directory to serve (default: ".")

**Flags:**
- `-p, --port int`: Listen port (default: 8000)
- `-b, --bind string`: Bind address (default: "")
- `-s, --https`: Enable HTTPS with auto-generated certificates
- `-m, --markdown`: Render `.md` files as HTML
- `--spa`: SPA mode — unmatched paths fall back to `index.html`
- `--php string`: PHP-FPM address (e.g. `127.0.0.1:9000` or `unix:/run/php-fpm.sock`)

**Examples:**
```bash
# Serve current directory
agbero serve

# Serve specific directory with HTTPS
agbero serve /var/www --https --port 8443

# Bind to specific interface
agbero serve . --bind 192.168.1.100 --port 9000
```

---

### `proxy` - Reverse Proxy
Proxy traffic to a local target instantly.

**Usage:**
```bash
agbero proxy <target> [domain] [flags]
```

**Arguments:**
- `target`: Target address (e.g., ":3000", "http://127.0.0.1:3000")
- `domain`: Domain name (default: "localhost") - optional positional argument

**Flags:**
- `-p, --port int`: Listen port (default: 8080)
- `-b, --bind string`: Bind address (default: "")
- `-s, --https`: Enable HTTPS with auto-generated certificates

**Examples:**
```bash
# Proxy local port 3000
agbero proxy :3000

# Proxy with custom domain
agbero proxy http://127.0.0.1:3000 app.localhost

# Proxy with HTTPS
agbero proxy :3000 --https --port 8443

# Bind to specific interface
agbero proxy :3000 --bind 192.168.1.100 --port 8443
```

---

## Help

### `help` - Show Usage Examples
Display usage examples and common workflows.

**Usage:**
```bash
agbero help
```

---

## Configuration Discovery Order

When `--config` is not specified, Agbero looks for `agbero.hcl` in this order:

1. Current working directory (`./agbero.hcl`)
2. User configuration directory (`~/.config/agbero/agbero.hcl`)
3. System configuration directory (`/etc/agbero/agbero.hcl`)

## Environment Variables

| Variable | Description | Source File |
|----------|-------------|-------------|
| `EDITOR` | Editor used by `config edit` and `home @editor` | `helper/configuration.go` |
| `AGBERO_HOME` | Override configuration home directory | `core/woos/paths.go` |

## Signal Handling

| Signal | Behavior |
|--------|----------|
| `SIGHUP` | Hot reload configuration (same as `config reload`) |
| `SIGTERM` | Graceful shutdown |
| `SIGINT` | Graceful shutdown (Ctrl+C) |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | General error |
| `2` | Invalid command or flags |

## Common Workflows

### Development Setup
```bash
# Initialize configuration
agbero init

# Run in foreground with auto-reload
agbero run --dev

# Add a route interactively
agbero host add

# Serve static files
agbero serve ./dist --https

# Proxy a dev server
agbero proxy :3000 --https
```

### Production Setup
```bash
# Install system-wide
sudo agbero service install

# Start service
sudo agbero service start

# Check status
sudo agbero service status

# After config changes, reload
sudo agbero config reload
```

### Cluster Setup
```bash
# Generate cluster secret
agbero secret cluster

# On seed node
agbero cluster start --config seed.hcl

# On joining node
agbero cluster join 192.168.1.10 --secret b64.encoded-key
```

### API Authentication Setup
```bash
# Generate master key
agbero secret key init

# Generate token for service
agbero secret token --service myapi --ttl 720h
```

### File Explorer Navigation
```bash
# Open various directories in file explorer
agbero home .
agbero home hosts .
agbero home certs .
agbero home logs .
```

### Shell Navigation
```bash
# Open shell in various directories
agbero home @
agbero home hosts @
agbero home certs @
cd $(agbero home work)
```