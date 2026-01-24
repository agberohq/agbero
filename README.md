# Agbero - Production Reverse Proxy

[![Go Report Card](https://goreportcard.com/badge/git.imaxinacion.net/aibox/agbero)](https://goreportcard.com/report/git.imaxinacion.net/aibox/agbero)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Agbero is a high-performance reverse proxy with automatic TLS (Let's Encrypt), gossip-based service discovery, and comprehensive middleware. Built in Go for production workloads.

## ✨ Features

- **Automatic TLS Management**: Let's Encrypt integration via CertMagic
- **Service Discovery**: HashiCorp Memberlist gossip protocol for dynamic service registration
- **Multiple Load Balancers**: Round-robin, random, least-connections strategies
- **HTTP/3 Ready**: QUIC support with automatic Alt-Svc headers
- **Comprehensive Middleware**:
  - Rate limiting with sharded maps for performance
  - Authentication (Basic & Forward auth)
  - Gzip/Brotli compression with connection pooling
  - Header manipulation
  - Client IP validation with trusted proxy support
- **Health Monitoring**: Configurable health checks with circuit breaker pattern
- **Detailed Metrics**: JSON metrics with HDR histogram latency tracking (P50, P90, P99)
- **Multi-Platform**: Linux (systemd), macOS (launchd), Windows service support

## 🚀 Quick Start

### Installation

```bash
# Build from source
git clone git@git.imaxinacion.net:aibox/agbero.git
cd agbero
make build

# Binary will be in bin/agbero
sudo cp bin/agbero /usr/local/bin/
```

### Basic Usage

```bash
# 1. Create configuration directory
sudo mkdir -p /etc/agbero/hosts.d

# 2. Generate default configuration
sudo agbero install --config /etc/agbero/config.hcl

# 3. Run in development mode
sudo agbero run --dev --config /etc/agbero/config.hcl
```

## 📋 Configuration

### Main Configuration (`/etc/agbero/config.hcl`)

```hcl
bind {
  http    = [":80", ":8080"]
  https   = [":443"]
  metrics = ":9090"
}

hosts_dir = "./hosts.d"
le_email = "admin@example.com"
trusted_proxies = ["127.0.0.1/32", "10.0.0.0/8"]

# Gossip service discovery
gossip {
  enabled         = true
  port            = 7946
  secret_key      = "your-32-byte-secret-here"  # Optional encryption
  private_key_file = "/etc/agbero/server.key"   # For service authentication
  seeds           = ["node1:7946", "node2:7946"] # Cluster peers
}

timeouts {
  read        = "10s"
  write       = "30s"
  idle        = "120s"
  read_header = "5s"
}

rate_limits {
  ttl         = "30m"
  max_entries = 100000
  
  global {
    requests = 120
    window   = "1s"
    burst    = 240
  }
  
  auth {
    requests = 10
    window   = "1m"
    burst    = 10
  }
}
```

### Host Configuration (`/etc/agbero/hosts.d/app.hcl`)

```hcl
domains = ["app.example.com", "*.example.com"]

route "/web/*" {
  # Static file serving
  web {
    root  = "/var/www/html"
    index = "index.html"
  }
}

# API routing with load balancing
route "/api/*" {
  backends = ["http://backend1:8080", "http://backend2:8080"]
  strip_prefixes = ["/api"]
  lb_strategy = "leastconn"
  
  health_check {
    path = "/health"
    interval = "30s"
    timeout = "5s"
  }
  
  circuit_breaker {
    threshold = 5
    duration = "30s"
  }
  
  # Basic authentication
  basic_auth {
    users = ["admin:$2y$10$hashedpassword"]
    realm = "Admin Area"
  }
}

# WebSocket support
route "/ws" {
  backends = ["http://websocket-backend:8080"]
  headers {
    request {
      set = {
        "Upgrade" = "websocket"
        "Connection" = "Upgrade"
      }
    }
  }
}
```

## 🔧 Service Discovery with Gossip

Agbero uses HashiCorp Memberlist for service discovery. Services can self-register:

### 1. Generate Server Key

```bash
# Generate Ed25519 key for signing service tokens
agbero key init
# Creates server.key file
```

### 2. Create Service Tokens

```bash
# Generate token for a service (valid 1 year)
agbero key gen --service api-service --ttl 8760h
# Output: JWT token for the service
```

### 3. Service Registration (Client Side)

Services join the gossip cluster by announcing themselves:

```go
// Example service joining the Agbero gossip cluster
import (
    "github.com/hashicorp/memberlist"
    "encoding/json"
)

type AppMeta struct {
    Token string `json:"token"`  // JWT from agbero key gen
    Port  int    `json:"port"`
    Host  string `json:"host"`   // e.g., "api.example.com"
    Path  string `json:"path"`   // e.g., "/api"
    StripPrefix bool `json:"strip,omitempty"`
}

func joinCluster() {
    config := memberlist.DefaultLANConfig()
    config.Name = "api-service-01"
    
    meta := AppMeta{
        Token: "eyJhbGciOiJFUzI1NiIs...", // Your JWT token
        Port:  3000,
        Host:  "api.example.com",
        Path:  "/api/v1",
        StripPrefix: true,
    }
    
    metaBytes, _ := json.Marshal(meta)
    config.Meta = metaBytes
    
    list, err := memberlist.Create(config)
    if err != nil {
        panic(err)
    }
    
    // Join Agbero node(s)
    _, err = list.Join([]string{"agbero-node:7946"})
    if err != nil {
        log.Printf("Failed to join cluster: %v", err)
    }
}
```

Once joined, Agbero will automatically:
- Validate the service's JWT token
- Add the route to its routing table
- Start load balancing traffic to the service
- Monitor health via regular pings

## 🛠️ Commands

```bash
# Service Management
agbero install --config /etc/agbero/config.hcl  # Install as system service
agbero start --config /etc/agbero/config.hcl    # Start service
agbero stop --config /etc/agbero/config.hcl     # Stop service
agbero uninstall --config /etc/agbero/config.hcl # Remove service

# Configuration
agbero validate --config /etc/agbero/config.hcl # Validate config
agbero hosts --config /etc/agbero/config.hcl    # List discovered hosts

# Key Management
agbero key init                                 # Generate server key
agbero key gen --service myservice --ttl 720h   # Create service token

# Development
agbero run --dev --config ./config.hcl          # Run interactively
agbero help --config /etc/agbero/config.hcl     # Show OS-specific examples
```

## 📊 Monitoring

### Metrics Endpoint

```bash
curl http://localhost:9090/metrics | jq .
```

Example metrics output:
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "hosts": {
    "api.example.com": {
      "total_reqs": 15432,
      "total_backends": 3,
      "avg_p99_us": 245,
      "routes": [
        {
          "path": "/api/v1",
          "strategy": "leastconn",
          "backends": [
            {
              "url": "http://10.0.1.5:3000",
              "alive": true,
              "in_flight": 2,
              "failures": 0,
              "total_reqs": 5144,
              "latency_us": {
                "p50": 45,
                "p90": 120,
                "p99": 250,
                "max": 500,
                "count": 5144,
                "avg_us": 52
              }
            }
          ]
        }
      ]
    }
  }
}
```

### Health Check

```bash
curl http://localhost:9090/health
# Returns: OK
```

## 🐳 Docker

```dockerfile
FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN make build

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/bin/agbero /usr/local/bin/agbero
COPY etc/agbero/ /etc/agbero/
EXPOSE 80 443 9090 7946
CMD ["agbero", "run", "--config", "/etc/agbero/config.hcl"]
```

## 🔧 Building from Source

```bash
# Clone
git clone git@git.imaxinacion.net:aibox/agbero.git
cd agbero

# Install dependencies
make deps

# Build for current platform
make build

# Cross-compile for all platforms
make build-all
# Outputs to bin/:
# - agbero-linux-amd64
# - agbero-linux-arm64  
# - agbero-windows-amd64.exe
# - agbero-darwin-amd64
# - agbero-darwin-arm64
```

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Your Service  │    │   Your Service  │    │   Your Service  │
│     (App 1)     │    │     (App 2)     │    │     (App 3)     │
└────────┬────────┘    └────────┬────────┘    └────────┬────────┘
         │                      │                      │
         └──────────────────────┼──────────────────────┘
                                │
                          ┌─────▼─────┐
                          │  HashiCorp │
                          │ Memberlist │
                          │ (Gossip)   │
                          └─────┬─────┘
                                │
                         ┌──────▼──────┐
                         │   AGBERO    │
                         │   Reverse   │
                         │    Proxy    │
                         └──────┬──────┘
                                │
                         ┌──────▼──────┐
                         │   Clients   │
                         │  (Users)    │
                         └─────────────┘
```

## 📁 Project Structure

```
agbero/
├── cmd/agbero/                 # CLI entry point
│   ├── main.go                # Command parsing
│   ├── helpers.go             # CLI utilities
│   └── service.go             # Service management
├── internal/                  # Core implementation
│   ├── discovery/            # Host & gossip discovery
│   │   ├── hosts.go          # File-based host config
│   │   └── gossip/           # HashiCorp Memberlist integration
│   ├── core/                 # Core utilities
│   │   ├── backend/          # Backend management
│   │   ├── metrics/          # HDR histogram metrics
│   │   ├── parser/           # HCL configuration
│   │   └── tls/              # TLS/CertMagic integration
│   ├── handlers/             # HTTP handlers
│   ├── middleware/           # Middleware stack
│   │   ├── ratelimit/        # Rate limiting
│   │   ├── auth/             # Authentication
│   │   ├── compress/         # Compression
│   │   └── clientip/         # Client IP handling
│   └── woos/                 # Types and constants
├── etc/agbero/               # Example configurations
├── Makefile                  # Build system
└── README.md                 # This file
```

## 🤝 Contributing

Contributions welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

MIT License - see [LICENSE](LICENSE) file.
```

## **`cmd/agbero/README.md` (CLI-specific)**

```markdown
# Agbero CLI Reference

Command-line interface for the Agbero reverse proxy.

## 📦 Installation

### Quick Install (Linux/macOS)

```bash
# Download latest release
curl -sSL https://git.imaxinacion.net/aibox/agbero/releases/latest/download/install.sh | bash

# Or manually
wget https://git.imaxinacion.net/aibox/agbero/releases/latest/download/agbero-linux-amd64
chmod +x agbero-linux-amd64
sudo mv agbero-linux-amd64 /usr/local/bin/agbero
```

### From Source

```bash
go install git.imaxinacion.net/aibox/agbero/cmd/agbero@latest
```

## 🎯 Usage

```bash
agbero [global-flags] <command> [command-flags]
```

### Global Flags

- `-c, --config string` - Configuration file path (default: OS-specific)
- `-d, --dev` - Enable development mode (staging certificates, debug logging)
- `-v, --version` - Show version
- `-h, --help` - Show help

### Commands

#### `run` - Run interactively
Run Agbero in foreground mode (development/testing).

```bash
agbero run --config ./config.hcl
agbero run --dev --config ./config.hcl
```

**Flags:**
- `--dev` - Use Let's Encrypt staging, enable debug logging

#### `install` - Install system service
Install Agbero as a system service.

```bash
# System service (requires sudo on Linux/macOS)
sudo agbero install --config /etc/agbero/config.hcl

# User service (macOS)
agbero install --config ~/.config/agbero/config.hcl
```

**Creates:**
- Linux: `/etc/systemd/system/agbero.service`
- macOS: `/Library/LaunchDaemons/agbero.plist` (system) or `~/Library/LaunchAgents/net.imaxinacion.agbero.plist` (user)
- Windows: `agbero` Windows Service

#### `start` - Start service
Start the installed service.

```bash
sudo agbero start --config /etc/agbero/config.hcl
```

#### `stop` - Stop service
Stop the running service.

```bash
sudo agbero stop --config /etc/agbero/config.hcl
```

#### `uninstall` - Remove service
Uninstall the service.

```bash
sudo agbero uninstall --config /etc/agbero/config.hcl
```

#### `validate` - Validate configuration
Validate configuration file syntax and hosts.

```bash
agbero validate --config /etc/agbero/config.hcl
```

#### `hosts` - List configured hosts
Show all discovered hosts (file-based + gossip).

```bash
agbero hosts --config /etc/agbero/config.hcl
```

#### `key` - Key management
Manage Ed25519 keys for gossip authentication.

```bash
# Generate server key
agbero key init

# Create service token
agbero key gen --service api --ttl 720h
```

**Subcommands:**
- `key init` - Generate server private key
- `key gen` - Create signed token for a service
    - `-s, --service string` - Service name (required)
    - `-t, --ttl duration` - Token validity (default: 8760h/1 year)

#### `help` - Show help examples
Display OS-specific usage examples.

```bash
agbero help --config /etc/agbero/config.hcl
```

## 📋 Examples by OS

### Linux (systemd)

```bash
# 1. Install
sudo mkdir -p /etc/agbero/hosts.d
sudo cp etc/agbero/config.hcl.example /etc/agbero/config.hcl
sudo agbero install --config /etc/agbero/config.hcl

# 2. Start
sudo systemctl start agbero
sudo systemctl enable agbero

# 3. Monitor
sudo journalctl -u agbero -f
sudo systemctl status agbero

# 4. Manage
sudo agbero stop --config /etc/agbero/config.hcl
sudo agbero start --config /etc/agbero/config.hcl
```

### macOS (launchd)

```bash
# System service (runs at boot)
sudo agbero install --config /etc/agbero/config.hcl
sudo launchctl load /Library/LaunchDaemons/agbero.plist

# User service (runs at login)
agbero install --config ~/.config/agbero/config.hcl
launchctl load ~/Library/LaunchAgents/net.imaxinacion.agbero.plist

# Check status
sudo launchctl list | grep agbero
launchctl list | grep agbero
```

### Windows

```powershell
# Run as Administrator
# 1. Create directory
mkdir C:\ProgramData\agbero

# 2. Install service
agbero install --config "C:\ProgramData\agbero\config.hcl"

# 3. Start
net start agbero

# 4. Manage
sc query agbero
net stop agbero
services.msc  # GUI management
```

## 🔧 Configuration Discovery

Agbero looks for configuration in:

1. **Command line**: `--config` flag
2. **Environment**: `AGBERO_CONFIG` variable
3. **Default paths**:
    - Linux/macOS: `/etc/agbero/config.hcl`
    - Windows: `C:\ProgramData\agbero\config.hcl`

## 🐛 Troubleshooting

### Common Issues

```bash
# 1. Permission errors (Linux/macOS)
sudo agbero install --config /etc/agbero/config.hcl

# 2. Port already in use
sudo lsof -i :80
sudo lsof -i :443
sudo kill -9 <PID>

# 3. Configuration errors
agbero validate --config /etc/agbero/config.hcl

# 4. Service not starting
sudo journalctl -u agbero -f  # Linux
sudo log show --predicate 'subsystem == "com.apple.launchd"'  # macOS
```

### Debug Mode

```bash
# Run with verbose logging
agbero run --dev --config ./config.hcl 2>&1 | tee agbero.log

# Check metrics
curl http://localhost:9090/metrics
curl http://localhost:9090/health
```

## 🔗 Related

- [Main Documentation](../README.md) - Full Agbero documentation
- [Configuration Guide](../docs/configuration.md) - HCL config format
- [Service Discovery](../docs/discovery.md) - Gossip protocol usage