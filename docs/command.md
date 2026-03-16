# Agbero CLI Reference

Complete documentation for the Agbero command-line interface.

## Global Flags

These flags can be used with any command:

| Flag | Description |
|------|-------------|
| `-c, --config string` | Path to configuration file (default: auto-detected) |
| `-d, --dev` | Enable development mode (debug logs, staging certificates) |
| `--version` | Show version information |
| `--help` | Show help for any command |

### Configuration Discovery Order

When `--config` is not specified, Agbero looks for `agbero.hcl` in this order:

1. Current working directory (`./agbero.hcl`)
2. User configuration directory (`~/.config/agbero/agbero.hcl`)
3. System configuration directory (`/etc/agbero/agbero.hcl`)

## Core Commands

### `run` - Run Agbero in foreground

Start Agbero interactively. Ideal for development, testing, or container environments.

**Usage:**
```bash
agbero run [flags]
```

**Flags:**
| Flag | Description |
|------|-------------|
| `-d, --dev` | Enable development mode |

**Examples:**
```bash
# Run with auto-detected config
agbero run

# Run with custom config in development mode
agbero run --config ./config/agbero.hcl --dev
```

**Behavior:**
- Loads and validates configuration
- Starts HTTP/HTTPS listeners based on `bind` settings
- Watches for host configuration changes in `hosts_dir`
- Supports hot reload via SIGHUP signal
- Blocks until SIGTERM or SIGINT is received

### `init` - Interactive Setup

Run the interactive setup wizard to create a new configuration.

**Usage:**
```bash
agbero init
```

**What it does:**
- Prompts for environment type (local/production)
- Creates directory structure (`hosts.d`, `certs.d`, `data.d`, `logs.d`, `work.d`)
- Generates secure admin password
- Creates internal auth key
- Sets up local CA (development mode)
- Writes default `agbero.hcl` configuration

**Example:**
```bash
agbero init
```

## Configuration Management

### `config validate` - Validate Configuration

Check the main config and all host files for syntax and validity.

**Usage:**
```bash
agbero config validate [flags]
```

**Examples:**
```bash
agbero config validate
agbero config validate --config ./custom/agbero.hcl
```

### `config reload` - Hot Reload

Send SIGHUP to running process to reload configuration without restart.

**Usage:**
```bash
agbero config reload [flags]
```

**Examples:**
```bash
# Reload system service
sudo agbero config reload

# Reload specific instance
agbero config reload --config ./agbero.hcl
```

**Note:** Requires `data_dir` to be set in config for PID file location.

### `config view` - View Configuration

Print the configuration file contents.

**Usage:**
```bash
agbero config view [flags]
```

**Flags:**
| Flag | Description |
|------|-------------|
| `-e, --editor string` | Open in specific editor (vim, nano, cat, etc.) |

**Examples:**
```bash
# Print to stdout
agbero config view

# View with specific editor
agbero config view --editor vim
agbero config view --editor "code -w"
```

### `config path` - Show Config Path

Display the resolved configuration file path.

**Usage:**
```bash
agbero config path [flags]
```

**Examples:**
```bash
agbero config path
# Output: /etc/agbero/agbero.hcl
```

### `config edit` - Edit Configuration

Open the configuration file in `$EDITOR`.

**Usage:**
```bash
agbero config edit [flags]
```

**Examples:**
```bash
# Uses $EDITOR environment variable
agbero config edit

# Falls back to vi if $EDITOR not set
```

## Secret & Key Management

### `secret cluster` - Generate Cluster Secret

Generate a 32-byte AES-256 compatible secret key for gossip encryption.

**Usage:**
```bash
agbero secret cluster
```

**Output:**
```
Generated 32-byte Secret Key (AES-256 compatible):
==================================================
b64.xVZ9k2mN8pQrS4tU6vW8xY0zA1bC3dE5fG7hI9jK=
==================================================

Usage in agbero.hcl:
gossip {
  secret_key = "b64.xVZ9k2mN8pQrS4tU6vW8xY0zA1bC3dE5fG7hI9jK="
}
```

### `secret key init` - Initialize Auth Key

Generate the master Ed25519 private key for internal service authentication.

**Usage:**
```bash
agbero secret key init [flags]
```

**Flags:**
| Flag | Description |
|------|-------------|
| `-c, --config string` | Path to config file (to read key location) |

**Examples:**
```bash
# Generate key at default location
agbero secret key init

# Generate key using path from config
agbero secret key init --config ./agbero.hcl
```

**Output:**
```
generated internal auth key: /etc/agbero/certs.d/internal_auth.key

security {
  enabled = true
  internal_auth_key = "/etc/agbero/certs.d/internal_auth.key"
}
```

### `secret token` - Generate API Token

Generate a signed JWT token for service-to-service authentication.

**Usage:**
```bash
agbero secret token [flags]
```

**Flags:**
| Flag | Description |
|------|-------------|
| `-s, --service string` | Service identifier (required) |
| `-t, --ttl duration` | Token validity duration (default: 8760h0m0s = 1 year) |
| `-c, --config string` | Path to config file |

**Examples:**
```bash
# Generate token valid for 1 year
agbero secret token --service myapp

# Generate token with custom TTL
agbero secret token --service myapp --ttl 24h

# Use specific config
agbero secret token --service myapp --config ./prod.hcl
```

**Output:**
```
API Token for service: myapp
Expires: 2025-03-15T10:30:00Z (8760h0m0s)
------------------------------------------------------------
eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdmMiOiJteWFwcCIsImlhdCI6MTcxMDUwMTAwMCwiZXhwIjoxNzQyMDM3MDAwfQ...
------------------------------------------------------------
```

### `secret hash` - Generate Password Hash

Generate a bcrypt hash of a password (for `basic_auth` users).

**Usage:**
```bash
agbero secret hash [flags]
```

**Flags:**
| Flag | Description |
|------|-------------|
| `-p, --password string` | Password to hash (prompts if omitted) |

**Examples:**
```bash
# Interactive password prompt
agbero secret hash

# Provide password directly
agbero secret hash --password "mysecret"
```

**Output:**
```
$2a$10$K2ul0gaUotcRRqTWnq4TRu06nxRo0yyO.ky8k..vpu2MgedAFLX4K
```

### `secret password` - Generate Random Password

Generate a secure random password and its bcrypt hash.

**Usage:**
```bash
agbero secret password [length]
```

**Arguments:**
| Argument | Description |
|----------|-------------|
| `length` | Password length (default: 32) |

**Examples:**
```bash
# Generate 32-character password
agbero secret password

# Generate 16-character password
agbero secret password 16
```

**Output:**
```
Generated Password:
==================================================
aB3$dE7fG9hJ1kL4mN6pQ8rS2tU5vW8xY
==================================================

Bcrypt Hash (for agbero.hcl basic_auth):
$2a$10$X9q8Y7zW6vU5tR4sS3pQ2oN1mL0kK9jJ8hH7gG6fF5dD4sS3aA2
```

## Host & Route Management

### `host list` - List Hosts

Display all configured hosts and their routes.

**Usage:**
```bash
agbero host list [flags]
```

**Flags:**
| Flag | Description |
|------|-------------|
| `-c, --config string` | Path to config file |

**Example:**
```bash
agbero host list
```

**Output:**
```
INFO[0000] configured host                           host_id=api domains="[api.example.com]" routes=3
INFO[0000] configured host                           host_id=admin domains="[admin.example.com]" routes=1
INFO[0000] configured host                           host_id=static domains="[static.example.com]" routes=2
```

### `host add` - Add Host (Interactive)

Interactively create a new host/route configuration.

**Usage:**
```bash
agbero host add [flags]
```

**Flags:**
| Flag | Description |
|------|-------------|
| `-c, --config string` | Path to config file |

**Interactive Prompts:**
1. Route Type: Reverse Proxy, Static Site, or TCP Proxy
2. Domain Name
3. Target/Directory/Backend Address
4. Listen Port (for TCP)

**Example:**
```bash
agbero host add
```

**Output:**
```
host created: /etc/agbero/hosts.d/app.localhost.hcl
Agbero daemon will pick up changes automatically.
```

### `host remove` - Remove Host (Interactive)

Interactively remove an existing host configuration.

**Usage:**
```bash
agbero host remove [flags]
```

**Flags:**
| Flag | Description |
|------|-------------|
| `-c, --config string` | Path to config file |

**Example:**
```bash
agbero host remove
# Select host from interactive list
```

**Output:**
```
removed host: app.localhost.hcl
```

## Certificate Management

### `cert install` - Install CA Certificate

Install the local Certificate Authority for development HTTPS.

**Usage:**
```bash
agbero cert install [flags]
```

**Flags:**
| Flag | Description |
|------|-------------|
| `-f, --force` | Force reinstall even if already installed |
| `-c, --config string` | Path to config file |

**Examples:**
```bash
# Install CA
agbero cert install

# Force reinstall
agbero cert install --force
```

### `cert uninstall` - Uninstall CA Certificate

Remove the local CA from system trust store and delete certificate files.

**Usage:**
```bash
agbero cert uninstall [flags]
```

**Flags:**
| Flag | Description |
|------|-------------|
| `-c, --config string` | Path to config file |

**Example:**
```bash
agbero cert uninstall
```

### `cert list` - List Certificates

Display all managed certificates.

**Usage:**
```bash
agbero cert list [flags]
```

**Flags:**
| Flag | Description |
|------|-------------|
| `-c, --config string` | Path to config file |

**Example:**
```bash
agbero cert list
```

**Output:**
```
found 3 certificates:
  1. ca-cert.pem
  2. localhost-443-cert.pem
  3. api.example.com.crt
```

### `cert info` - Certificate Information

Show detailed certificate store information.

**Usage:**
```bash
agbero cert info [flags]
```

**Flags:**
| Flag | Description |
|------|-------------|
| `-d, --dir string` | Override certificate directory |
| `-c, --config string` | Path to config file |

**Example:**
```bash
agbero cert info
```

**Output:**
```
CERTIFICATE INFORMATION
Store Listing: /etc/agbero/certs.d
  • ca-cert.pem (1.2 KB, 2024-01-01)
  • localhost-443-cert.pem (1.1 KB, 2024-01-01)
  • api.example.com.crt (1.8 KB, 2024-01-15)
```

## Service Management

### `service install` - Install System Service

Install Agbero as a system service (requires appropriate privileges).

**Usage:**
```bash
agbero service install [flags]
```

**Flags:**
| Flag | Description |
|------|-------------|
| `--here` | Install configuration in current directory only (skip service) |
| `-c, --config string` | Path to config file |

**Examples:**
```bash
# System-wide installation (requires sudo)
sudo agbero service install

# Local configuration only (no service)
agbero service install --here
```

### `service uninstall` - Uninstall System Service

Remove the system service.

**Usage:**
```bash
agbero service uninstall [flags]
```

**Example:**
```bash
sudo agbero service uninstall
```

### `service start` - Start Service

Start the Agbero system service.

**Usage:**
```bash
agbero service start [flags]
```

**Example:**
```bash
sudo agbero service start
```

### `service stop` - Stop Service

Stop the Agbero system service.

**Usage:**
```bash
agbero service stop [flags]
```

**Example:**
```bash
sudo agbero service stop
```

### `service restart` - Restart Service

Restart the Agbero system service.

**Usage:**
```bash
agbero service restart [flags]
```

**Example:**
```bash
sudo agbero service restart
```

### `service status` - Check Service Status

Display the current status of the Agbero service.

**Usage:**
```bash
agbero service status [flags]
```

**Flags:**
| Flag | Description |
|------|-------------|
| `-c, --config string` | Path to config file (for PID lookup) |

**Example:**
```bash
sudo agbero service status
```

**Output:**
```
INFO[0000] service status: running
INFO[0000] process ID: 12345
```

## Cluster Management

### `cluster start` - Start Cluster Seed

Start Agbero as a cluster seed node.

**Usage:**
```bash
agbero cluster start [flags]
```

**Flags:**
| Flag | Description |
|------|-------------|
| `-c, --config string` | Path to config file |

**Example:**
```bash
agbero cluster start --config ./seed.hcl
```

### `cluster join` - Join Cluster

Join an existing Agbero cluster.

**Usage:**
```bash
agbero cluster join <ip> [flags]
```

**Arguments:**
| Argument | Description |
|----------|-------------|
| `ip` | IP address of the cluster seed node |

**Flags:**
| Flag | Description |
|------|-------------|
| `-s, --secret string` | Cluster secret key |
| `-c, --config string` | Path to config file |

**Examples:**
```bash
agbero cluster join 192.168.1.10 --secret b64.xVZ9k2mN8pQrS4tU6vW8xY0zA1bC3dE5fG7hI9jK=
```

## Ephemeral Commands

### `serve` - Static File Server

Serve a static directory instantly without persistent configuration.

**Usage:**
```bash
agbero serve [path] [flags]
```

**Arguments:**
| Argument | Description |
|----------|-------------|
| `path` | Directory to serve (default: ".") |

**Flags:**
| Flag | Description |
|------|-------------|
| `-p, --port int` | Listen port (default: 8000) |
| `-b, --bind string` | Bind address (default: "") |
| `-s, --https` | Enable HTTPS with auto-generated certificates |

**Examples:**
```bash
# Serve current directory on port 8000
agbero serve

# Serve /var/www on port 8080
agbero serve /var/www --port 8080

# Serve with HTTPS
agbero serve . --https

# Bind to specific interface
agbero serve . --bind 192.168.1.100 --port 9000
```

### `proxy` - Reverse Proxy

Proxy traffic to a local target instantly.

**Usage:**
```bash
agbero proxy <target> [domain] [flags]
```

**Arguments:**
| Argument | Description |
|----------|-------------|
| `target` | Target address (e.g., ":3000", "http://127.0.0.1:3000") |
| `domain` | Domain name (default: "localhost") |

**Flags:**
| Flag | Description |
|------|-------------|
| `-p, --port int` | Listen port (default: 8080) |
| `-b, --bind string` | Bind address (default: "") |
| `-s, --https` | Enable HTTPS with auto-generated certificates |

**Examples:**
```bash
# Proxy local port 3000
agbero proxy :3000

# Proxy with custom domain
agbero proxy http://127.0.0.1:3000 app.localhost

# Proxy with HTTPS
agbero proxy :3000 --https --port 8443

# Bind to specific interface
agbero proxy :3000 --bind 192.168.1.100
```

## Navigation

### `home` - Configuration Directory

Print or navigate to Agbero configuration directories.

**Usage:**
```bash
agbero home [target] [action]
```

**Arguments:**
| Argument | Description |
|----------|-------------|
| `target` | Directory: `hosts`, `certs`, `data`, `logs`, `work`, `config` (default: root) |
| `action` | `@` to open shell, or `@editor` to view/edit |

**Examples:**
```bash
# Show root directory path
agbero home

# Open shell in root directory
agbero home @

# Show config file path
agbero home config

# View config file
agbero home config @cat

# Edit config with vim
agbero home config @vim

# Navigate to hosts directory
cd $(agbero home hosts)

# Open shell in certs directory
agbero home certs @
```

## Help

### `help` - Show Examples

Display usage examples and common workflows.

**Usage:**
```bash
agbero help
```

**Output:**
```
agbero - High-performance reverse proxy / load balancer with TLS v1.0.0

===============================================================
USAGE EXAMPLES
===============================================================

SCAFFOLDING:
  agbero init                        # scaffold config in current folder
  agbero service install             # install config + system service

EXECUTION:
  agbero run                         # run using discovered config
  agbero serve .                     # serve current directory on the fly
  agbero proxy :3000                 # proxy local port 3000

CONFIGURATION:
  agbero config validate             # validate config file
  agbero config view                 # print config file
  agbero config edit                 # edit config in $EDITOR
  agbero config path                 # show config file path
  agbero config reload               # hot reload running instance

SECRETS & KEYS:
  agbero secret cluster              # generate gossip secret key
  agbero secret key init             # generate internal auth key
  agbero secret token -s myapp       # generate API token for 'myapp'
  agbero secret hash -p mypass       # bcrypt hash a password
  agbero secret password             # generate random password + hash

HOSTS:
  agbero host list                   # list configured hosts
  agbero host add                    # add host/route (interactive)
  agbero host remove                 # remove host/route (interactive)

NAVIGATION:
  agbero home                        # print Agbero home directory
  agbero home @                      # open shell in home directory
  agbero home hosts @                # open shell in hosts.d
  
  agbero home .                      # open home directory
  agbero home hosts .                # open hosts.d 
  

SERVICE MANAGEMENT:
  sudo agbero service install
  sudo agbero service start
  sudo agbero service stop
  sudo agbero service restart
  sudo agbero service status
  sudo agbero service uninstall
```

## Signal Handling

Agbero responds to the following signals:

| Signal | Behavior |
|--------|----------|
| `SIGHUP` | Hot reload configuration (same as `config reload`) |
| `SIGTERM` | Graceful shutdown - wait for active requests, then exit |
| `SIGINT` | Graceful shutdown (Ctrl+C) |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | General error (config error, runtime error) |
| `2` | Invalid command or flags |
| `3` | Permission denied |
| `4` | Configuration not found |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `EDITOR` | Editor used by `config edit` and `home @editor` |
| `AGBERO_HOME` | Override configuration home directory |

## Common Workflows

### Development Setup
```bash
# Init in default location
agbero init

# Init in a specific directory
AGBERO_HOME=/etc/agbero agbero init

# Run
agbero run

# Run in foreground
agbero run --dev
```

### Production Setup
```bash
# Install system-wide
sudo agbero service install

# Start service
sudo agbero service start

# Check status
sudo agbero service status

# After config changes
sudo agbero config reload
# or
sudo agbero service restart
```

### Cluster Setup
```bash
# On seed node
agbero cluster start --config seed.hcl

# On joining node
agbero cluster join 192.168.1.10 --secret b64.xxx

# Generate cluster secret
agbero secret cluster
```

### API Authentication Setup
```bash
# Generate master key
agbero secret key init

# Generate token for service
agbero secret token --service myapi --ttl 720h
```

### Quick Ephemeral Usage
```bash
# Serve static files
agbero serve ./dist --https

# Proxy development server
agbero proxy :3000 --https

# Test configuration changes
agbero config validate
agbero config reload
```