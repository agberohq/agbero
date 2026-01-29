# Agbero CLI Reference

Complete documentation for the Agbero command-line interface.

## Installation

### From Binary Release
```bash
# Linux/macOS
curl -L https://github.com/yourorg/agbero/releases/latest/download/agbero-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m) -o agbero
chmod +x agbero
sudo mv agbero /usr/local/bin/

# Verify installation
agbero --version
```

### From Source
```bash
go install git.imaxinacion.net/aibox/agbero/cmd/agbero@latest
```

## Global Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-c, --config` | Path to configuration file | Auto-detected |
| `-d, --dev` | Enable development mode | `false` |
| `--version` | Show version information | N/A |
| `--help` | Show help | N/A |

## Commands Overview

### 🚀 `run` - Run in foreground
Run Agbero interactively (perfect for development).

**Usage:**
```bash
agbero run [flags]
```

**Examples:**
```bash
# Simple development server
agbero run

# With custom config
agbero run --config ./my-config.hcl

# Development mode (debug logs, staging certificates)
agbero run --dev --config ./config.hcl

# Enable gossip clustering
agbero run --gossip --config cluster-config.hcl
```

**What happens:**
1. Configuration is validated and loaded
2. Missing directories are created
3. TLS certificates are generated if needed
4. Server starts listening on configured ports
5. File watchers monitor configuration changes

**Exit codes:**
- `0`: Clean shutdown
- `1`: Configuration error
- `2`: Runtime error
- `130`: Interrupted by signal

---

### 🔧 `install` - Install as system service
Install Agbero as a background service for your OS.

**Usage:**
```bash
agbero install [flags]
```

**Interactive installation:**
```bash
agbero install
```
You'll be prompted to choose installation type:
- **System** (`/etc/agbero/`) - Requires sudo, runs as root
- **User** (`~/.config/agbero/`) - No sudo, runs as your user
- **Current Directory** - For testing, uses CWD

**Examples:**
```bash
# System installation (Linux/macOS)
sudo agbero install --config /etc/agbero/config.hcl

# User installation (no sudo)
agbero install --config ~/.config/agbero/config.hcl

# Custom path
agbero install --config /opt/agbero/config.hcl

# With development mode
agbero install --dev --config ./config.hcl
```

**Supported platforms:**
- **Linux**: Systemd (`/etc/systemd/system/agbero.service`)
- **macOS**: Launchd (`/Library/LaunchDaemons/net.imaxinacion.agbero.plist`)
- **Windows**: Windows Service (`Agbero Service`)

**Service management after installation:**
```bash
# Linux
sudo systemctl status agbero
sudo systemctl restart agbero
sudo journalctl -u agbero -f

# macOS
sudo launchctl list | grep agbero
sudo launchctl unload /Library/LaunchDaemons/net.imaxinacion.agbero.plist

# Windows
sc query agbero
sc stop agbero
```

---

### ⚡ `start` / `stop` / `restart` - Service control
Control the installed Agbero service.

**Usage:**
```bash
agbero start [flags]
agbero stop [flags]
agbero restart [flags]
```

**Examples:**
```bash
# Start the service
sudo agbero start --config /etc/agbero/config.hcl

# Stop the service
sudo agbero stop --config /etc/agbero/config.hcl

# Restart (reloads configuration)
sudo agbero restart --config /etc/agbero/config.hcl
```

**Note:** Configuration path must match what was used during `install`.

---

### 🗑️ `uninstall` - Remove service
Remove Agbero service from your system.

**Usage:**
```bash
agbero uninstall [flags]
```

**Examples:**
```bash
# Uninstall system service
sudo agbero uninstall --config /etc/agbero/config.hcl

# Uninstall user service
agbero uninstall --config ~/.config/agbero/config.hcl
```

**What happens:**
1. Service is stopped
2. Service definition is removed
3. **Configuration files are preserved**
4. Certificate files are preserved

---

### ✅ `validate` - Validate configuration
Check configuration files for syntax errors and validity.

**Usage:**
```bash
agbero validate [flags]
```

**Examples:**
```bash
# Validate default config
agbero validate

# Validate specific config
agbero validate --config ./config.hcl

# Validate with verbose output
agbero validate --config ./config.hcl -v
```

**Output:**
```
✅ Configuration is valid
  Config file: /etc/agbero/config.hcl
  Hosts loaded: 5
  Routes: 12
  TLS certificates: 3
```

**Exit codes:**
- `0`: Configuration is valid
- `1`: Configuration has errors (details shown)

---

### 📋 `hosts` - List configured hosts
Display all discovered host configurations.

**Usage:**
```bash
agbero hosts [flags]
```

**Examples:**
```bash
# List all hosts
agbero hosts --config ./config.hcl

# Output format
agbero hosts --config ./config.hcl --json
```

**Sample output:**
```
HOST CONFIGURATIONS
===================

api.example.com
  Config: api.hcl
  Routes: 3
    • /api/v1/users → http://backend:8080
    • /api/v1/orders → http://backend:8080
    • /static/* → ./public (web)

app.example.com
  Config: app.hcl  
  Routes: 1
    • / → ./dist (web)

Total: 2 hosts, 4 routes
```

---

### 🔐 `hash` - Generate password hash
Generate bcrypt hashes for Basic Authentication.

**Usage:**
```bash
agbero hash [flags]
```

**Examples:**
```bash
# Interactive prompt
agbero hash
# Enter password: ******

# Direct password
agbero hash --password "mysecret"

# With custom cost
agbero hash --password "mysecret" --cost 12
```

**Output:**
```
Bcrypt Hash:
$2a$10$N9qo8uLOickgx2ZMRZoMye.Md5cKXzqGc9LpBqQ6GpUJYx5e4vY1C

Usage in config:
users = ["admin:$2a$10$N9qo8uLOickgx2ZMRZoMye.Md5cKXzqGc9LpBqQ6GpUJYx5e4vY1C"]
```

---

## Gossip Commands

### 🔄 `gossip init` - Initialize gossip cluster
Generate gossip private key and show configuration.

**Usage:**
```bash
agbero gossip init [flags]
```

**Examples:**
```bash
# Initialize with default config
agbero gossip init --config ./config.hcl

# Specify custom key location
agbero gossip init --key ./custom-gossip.key
```

**What happens:**
1. Ed25519 key pair is generated
2. Key is saved to configured location
3. Sample configuration is shown

**Output:**
```
Generated gossip key: /etc/agbero/gossip.key

Add to your config.hcl:
gossip {
  enabled = true
  port    = 7946
  private_key_file = "/etc/agbero/gossip.key"
  seeds = ["node2:7946", "node3:7946"]
}
```

---

### 🎫 `gossip token` - Generate service token
Create JWT tokens for service authentication.

**Usage:**
```bash
agbero gossip token [flags]
```

**Flags:**
- `-s, --service`: Service name (required)
- `-t, --ttl`: Token TTL (default: `720h` = 30 days)
- `--config`: Configuration file path

**Examples:**
```bash
# Generate 30-day token
agbero gossip token --service payment-api --config ./config.hcl

# 7-day token
agbero gossip token --service user-api --ttl 168h --config ./config.hcl

# Output only token (for scripting)
agbero gossip token --service auth-service --quiet
```

**Sample token output:**
```
eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJwYXltZW50LWFwaS...

Use in your service metadata:
{"token":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...","port":8080,"host":"payment.internal"}
```

---

### 📊 `gossip status` - Show gossip status
Display current gossip cluster status and configuration.

**Usage:**
```bash
agbero gossip status [flags]
```

**Examples:**
```bash
# Check status
agbero gossip status --config ./config.hcl

# Detailed output
agbero gossip status --config ./config.hcl --verbose
```

**Sample output:**
```
GOSSIP STATUS
=============

Configuration:
  Enabled: YES
  Port: 7946
  Private key: /etc/agbero/gossip.key (VALID)
  Encryption: DISABLED
  Seeds: node2:7946, node3:7946

Cluster:
  Members: 3
    • agbero-node1 (self)
    • agbero-node2 (alive, 1s ago)
    • payment-api (alive, 5s ago)

Discovered Services:
  • payment-api → payment.internal:8080 (/api)
  • user-api → users.internal:8081 (/users)
```

---

## Certificate Commands

### 📜 `cert` - Certificate management
Manage TLS certificates and CA.

**Subcommands:**
- `cert install-ca` - Install local CA certificate
- `cert list` - List generated certificates
- `cert info` - Show certificate information

---

### `cert install-ca` - Install local CA
Install mkcert CA root to system trust store.

**Usage:**
```bash
agbero cert install-ca [flags]
```

**Flags:**
- `-f, --force`: Force reinstall
- `-m, --method`: Installation method (`auto|mkcert|truststore`)

**Examples:**
```bash
# Install CA
agbero cert install-ca --config ./config.hcl

# Force reinstall
agbero cert install-ca --force --config ./config.hcl

# Specific method
agbero cert install-ca --method mkcert --config ./config.hcl
```

**Platform support:**
- **macOS**: Installs to system keychain
- **Linux**: Installs to system CA store
- **Windows**: Installs to certificate store

---

### `cert list` - List certificates
Show all certificates in the certificate directory.

**Usage:**
```bash
agbero cert list [flags]
```

**Examples:**
```bash
# List certificates
agbero cert list --config ./config.hcl

# With directory override
agbero cert list --dir ./certs
```

**Sample output:**
```
CERTIFICATES
============

Directory: /etc/agbero/certs

1. localhost-8443-cert.pem
   • Size: 2.1 KB
   • Modified: 2024-01-15 14:30:22
   • SANs: localhost, *.localhost, 127.0.0.1, ::1

2. example.localhost-443-cert.pem
   • Size: 2.2 KB  
   • Modified: 2024-01-15 14:35:10
   • SANs: example.localhost

Total: 2 certificates
```

---

### `cert info` - Certificate information
Show detailed certificate information.

**Usage:**
```bash
agbero cert info [flags]
```

**Examples:**
```bash
# Show cert info from config
agbero cert info --config ./config.hcl

# Specific directory
agbero cert info --dir ./certs
```

---

## Key Management Commands

### 🔑 `key` - Key management
Manage cryptographic keys for gossip and tokens.

**Subcommands:**
- `key init` - Generate new private key
- `key gen` - Generate token from existing key

---

### `key init` - Initialize key
Generate a new Ed25519 private key.

**Usage:**
```bash
agbero key init [flags]
```

**Examples:**
```bash
# Generate default key
agbero key init --config ./config.hcl

# Custom output path
agbero key init --output ./custom.key
```

**Output:**
```
Generated private key: /etc/agbero/gossip.key
File mode: 0600 (read/write owner only)
```

---

### `key gen` - Generate token
Create a JWT token using existing private key.

**Usage:**
```bash
agbero key gen [flags]
```

**Flags:**
- `-s, --service`: Service name (required)
- `-t, --ttl`: Token TTL (default: `720h`)
- `--config`: Configuration file

**Examples:**
```bash
# Generate token
agbero key gen --service my-app --config ./config.hcl

# Custom TTL
agbero key gen --service my-app --ttl 24h --config ./config.hcl
```

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AGBERO_CONFIG` | Configuration file path | Auto-detected |
| `AGBERO_DEV` | Enable development mode | `0` |
| `AGBERO_LOG_LEVEL` | Log level | `info` |
| `HOME` | User home directory | System default |
| `USER` | Current user | System default |

**Example:**
```bash
export AGBERO_CONFIG=/etc/agbero/config.hcl
export AGBERO_DEV=1
agbero run
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Generic error |
| `2` | Configuration error |
| `3` | Service error |
| `4` | Certificate error |
| `5` | Network error |
| `130` | Interrupted (Ctrl+C) |
| `143` | Terminated |

---

## Configuration Discovery Order

When `--config` is not specified, Agbero searches:

1. **Command line flag**: `--config /path/to/config.hcl`
2. **Environment variable**: `AGBERO_CONFIG`
3. **Current directory**: `./agbero.hcl`
4. **User config**: `~/.config/agbero/agbero.hcl`
5. **System config**: `/etc/agbero/agbero.hcl`
6. **Fallback**: Current directory with auto-generation

---

## Examples

### Complete Development Setup
```bash
# 1. Navigate to project
cd ~/projects/myapp

# 2. Generate config and start
agbero run --dev

# 3. Install as user service
agbero install

# 4. Start service
agbero start
```

### Production Deployment
```bash
# 1. Install system-wide
sudo agbero install --config /etc/agbero/config.hcl

# 2. Validate config
sudo agbero validate --config /etc/agbero/config.hcl

# 3. Start service
sudo agbero start --config /etc/agbero/config.hcl

# 4. Check status
sudo agbero gossip status --config /etc/agbero/config.hcl
```

### Generate Service Tokens
```bash
# Generate tokens for all services
agbero gossip token --service api-gateway > api-token.txt
agbero gossip token --service payment-service > payment-token.txt
agbero gossip token --service user-service > user-token.txt
```

---

## Troubleshooting

### Service Won't Start
```bash
# Check logs
sudo journalctl -u agbero -f

# Validate config
sudo agbero validate --config /etc/agbero/config.hcl

# Run in foreground to see errors
sudo agbero run --config /etc/agbero/config.hcl
```

### Certificate Issues
```bash
# Install CA
agbero cert install-ca --force

# Check existing certs
agbero cert list

# Run with dev mode to regenerate
agbero run --dev
```

### Gossip Not Working
```bash
# Check status
agbero gossip status

# Verify ports
sudo lsof -i :7946
sudo netstat -an | grep 7946

# Regenerate key
agbero gossip init --force
```

---

## Tips & Best Practices

1. **Use `--dev` flag** during development for auto-TLS
2. **Validate config** before installing as service
3. **Store tokens securely** - never commit to git
4. **Use environment variables** for secrets
5. **Check `agbero gossip status`** after cluster changes
6. **Monitor with `journalctl`** on Linux systems