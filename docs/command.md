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
| `secret key init` | Generate master private key for internal auth (requires keeper to be unlocked) |
| `secret token` | Generate signed Ed25519 API token for a service (requires keeper to be unlocked) |
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

---

## Keeper (Encrypted Secret Store)

### `keeper` — Manage the Encrypted Secret Store

The keeper is Agbero's built-in encrypted secret store. It holds credentials, API keys, TLS certificates, and the internal auth key. It is passphrase-protected and must be unlocked before Agbero can start.

Running `agbero keeper` with no subcommand opens an interactive REPL.

**Subcommands:**

| Command | Description |
|---------|-------------|
| `keeper` *(no subcommand)* | Open interactive REPL |
| `keeper list` | List all keys in the keeper |
| `keeper get <key>` | Retrieve a value from the keeper |
| `keeper set <key> [value]` | Store a value in the keeper |
| `keeper delete <key>` | Delete a key from the keeper |
| `keeper rotate` | Change the master passphrase (re-encrypts all secrets in place) |
| `keeper help` | Show keeper command reference |

**Usage:**
```bash
agbero keeper <subcommand> [flags]
```

**Flags for `set`:**
- `-f, --file string`: Read value from file (e.g. a certificate or SSH key PEM)
- `-b, --b64`: Value is already base64-encoded — decode it before storing

**Key format:** `namespace/key` or `ss://namespace/key`

**Passphrase resolution order (at startup):**
1. `keeper.passphrase` field in `agbero.hcl`
2. `AGBERO_PASSPHRASE` environment variable
3. Interactive terminal prompt (if running in a terminal)

**Examples:**
```bash
# Open the interactive REPL
agbero keeper

# List all stored keys
agbero keeper list

# Retrieve a secret value
agbero keeper get myapp/db-password

# Store a plain-text value
agbero keeper set myapp/db-password "s3cr3t"

# Store a certificate from a file
agbero keeper set certs/my-cert --file ./cert.pem

# Store a pre-encoded base64 value (decode it first)
agbero keeper set myapp/key "dGVzdA==" --b64

# Delete a secret
agbero keeper delete myapp/db-password

# Change the master passphrase (re-encrypts everything)
agbero keeper rotate
```
### Rotating the Master Passphrase

`agbero keeper rotate` changes the master passphrase and re-encrypts all stored secrets with the new passphrase. Here is the safe procedure:

```bash
# 1. Stop the running Agbero instance first
sudo agbero service stop

# 2. Run the rotation (prompts for current passphrase, then new passphrase twice)
agbero keeper rotate

# 3. Update your passphrase wherever it is stored:
#    - Update AGBERO_PASSPHRASE in your system service environment
#    - Update the secret in your secrets manager / CI environment
#    - Update agbero.hcl if you hardcoded it (please don't)

# 4. Restart Agbero with the new passphrase
AGBERO_PASSPHRASE=newpassphrase sudo agbero service start
```

> **Important notes:**
> - Stop Agbero before rotating. Rotating while the server is running is safe from a data perspective (it uses a transaction) but the running process holds the old passphrase in memory and will fail on the next unlock cycle.
> - In a cluster, run rotation on each node separately while that node is stopped. Nodes do not automatically share passphrase changes — each node's `keeper.db` is encrypted with its own passphrase. After rotation on all nodes, bring them back up one at a time.
> - If rotation fails partway through (power loss, crash), the database is left in a consistent state on the old passphrase. Re-run `agbero keeper rotate` to complete it.



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

---

## Admin Commands

### `admin` — Manage Admin Users and Authentication

**Subcommands:**

| Command | Description |
|---------|-------------|
| `admin totp setup` | Generate and store a new TOTP secret for an admin user |
| `admin totp qr` | Re-display the TOTP QR code for an admin user |

**Usage:**
```bash
agbero admin <subcommand> [flags]
```

**Flags for both `totp setup` and `totp qr`:**
- `-u, --user string`: Admin username
- `-o, --out string`: Write QR code PNG to this file path

**Examples:**
```bash
# Set up TOTP for admin user "alice" — displays QR code in terminal
agbero admin totp setup --user alice

# Re-display the QR code for an existing user
agbero admin totp qr --user alice

# Save the QR code as a PNG file
agbero admin totp qr --user alice --out qr.png
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
| `cert delete <domain>` | Delete a certificate for a domain from the store |

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

Clustering in Agbero is configured entirely in `agbero.hcl` via the `gossip` block — there are **no separate cluster CLI commands**. Nodes discover each other through the `seeds` list in the config.

The only cluster-related CLI command is generating the shared secret key:

```bash
# Generate a cryptographically random 32-byte cluster key
agbero secret cluster
# Output: b64.xVZ9k2mN8pQrS4tU6vW8xY0zA1bC3dE5fG7hI9jK=

# Then add it to agbero.hcl on every node:
#   gossip {
#     enabled    = true
#     secret_key = "b64.xVZ9k2mN8pQrS4tU6vW8xY0zA1bC3dE5fG7hI9jK="
#     seeds      = ["node2:7946", "node3:7946"]
#   }
# Nodes join the cluster automatically on startup — no manual join command needed
```

See the [Advanced Guide](./advance.md) for full gossip and clustering configuration.

---

---

## System Commands

### `system` — System-Level Operations

**Subcommands:**

| Command | Description |
|---------|-------------|
| `system backup` | Backup configurations, certificates, and data to a password-encrypted zip |
| `system restore` | Restore from a backup zip |
| `system update` | Download and apply the latest release from GitHub |

**Usage:**
```bash
agbero system <subcommand> [flags]
```

**Flags for `backup`:**
- `-o, --out string`: Output zip file path (default: `agbero_backup_<timestamp>.zip`)
- `-p, --password string`: Password for AES-256 encryption

**Flags for `restore`:**
- `-i, --in string`: Input zip file path (required)
- `-p, --password string`: Password for AES-256 decryption
- `-f, --force`: Force overwrite of existing files without prompting
- `-y, --yes`: Skip top-level confirmation prompt

**Flags for `update`:**
- `-f, --force`: Apply even if already on the latest version
- `-y, --yes`: Skip confirmation prompt

**Examples:**
```bash
# Create an encrypted backup
agbero system backup --out backup.zip --password mypass

# Restore from backup
agbero system restore --in backup.zip --password mypass

# Restore and overwrite without prompting
agbero system restore --in backup.zip --password mypass --force --yes

# Update to the latest release
agbero system update

# Update without being asked to confirm
agbero system update --force --yes
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
| `AGBERO_PASSPHRASE` | Master passphrase for the keeper. Required in non-interactive environments (system services, containers, CI). | `hub/secrets/keeper.go` |
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
# Generate cluster secret key
agbero secret cluster

# Add to agbero.hcl on every node:
#   gossip {
#     enabled    = true
#     secret_key = "b64...."
#     seeds      = ["node2:7946"]
#   }
# Nodes join the cluster automatically on startup via the seeds list
```

### API Authentication Setup
```bash
# Generate master key (stored securely in the keeper)
agbero secret key init

# Generate a service token
agbero secret token --service myapi --ttl 720h
# IMPORTANT: Keep the JTI shown in the output — you need it to revoke via POST /api/v1/auto/revoke
```

### Keeper Operations
```bash
# List all stored secrets
agbero keeper list

# Store a plain value
agbero keeper set myapp/stripe-key "sk_live_..."

# Store a file (e.g. a TLS certificate)
agbero keeper set ssl/cert --file ./cert.pem

# Change the master passphrase
agbero keeper rotate
```

### Admin TOTP Setup
```bash
# Generate TOTP secret for a user and show QR code in terminal
agbero admin totp setup --user alice

# Re-display QR code and also save it as a PNG
agbero admin totp qr --user alice --out qr.png
```

### Backup and Restore
```bash
# Create an encrypted backup of all config, certs, and data
agbero system backup --out backup.zip --password mypass

# Restore from backup
agbero system restore --in backup.zip --password mypass
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