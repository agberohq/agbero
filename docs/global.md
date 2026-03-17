# Agbero Global Configuration (agbero.hcl)

This file is the main configuration for the agbero proxy. Host-specific configurations belong in `hosts.d/*.hcl`.

## Configuration Basics

### Schema Version
```hcl
version = 1
```
The configuration schema version. Must match the version expected by your Agbero binary.

### Development Mode
```hcl
development = true   # or false
```
Enables debug logging, verbose errors, and relaxed TLS settings. **Disable in production.**

## Understanding `enabled` Fields

Agbero uses a flexible `Enabled` type that accepts multiple formats:

| Value Type | Active Examples | Inactive Examples | Unknown |
|------------|----------------|-------------------|---------|
| Strings | `"on"`, `"true"`, `"enabled"`, `"enable"`, `"yes"` | `"off"`, `"false"`, `"disabled"`, `"disable"`, `"no"` | `"unknown"`, `"default"`, `""` |
| Booleans | `true` | `false` | - |
| Integers | `1` | `-1` | `0` |

**Examples:**
```hcl
enabled = "on"           # Active
enabled = true         # Active
enabled = 1            # Active
enabled = "off"          # Inactive
enabled = false        # Inactive
enabled = -1           # Inactive
enabled = unknown      # Use default behavior
enabled = ""           # Use default behavior
```

## 1. BINDING ADDRESSES

Controls which ports and interfaces Agbero listens on.

```hcl
bind {
  # HTTP listeners (plain text, usually redirects to HTTPS)
  http = [":80", ":8080"]        # Listen on all interfaces
  # http = ["127.0.0.1:80"]      # Listen only on localhost

  # HTTPS/HTTP3 listeners (TLS required)
  https = [":443", ":8443"]

  # Automatically redirect HTTP -> HTTPS
  redirect = "on"   # on, off, true, false, 1, -1
}
```

- **`http`**: List of addresses for HTTP (unencrypted) connections
- **`https`**: List of addresses for HTTPS (TLS) and HTTP/3 connections
- **`redirect`**: When `on`, HTTP requests are automatically redirected to HTTPS

## 2. ADMIN INTERFACE

The administrative dashboard and API for monitoring and managing Agbero.

```hcl
admin {
  # Enable admin UI and API endpoints
  enabled = "on"

  # Admin interface bind address
  address = ":9090"

  # Restrict admin access to specific IPs/CIDRs
  allowed_ips = ["127.0.0.1", "::1", "192.168.1.0/24"]

  # Enable pprof debugging endpoints (security risk in production)
  pprof = "off"

  # Basic authentication for the /login endpoint
  basic_auth {
    enabled = "on"
    # Format: "username:bcrypt_hash"
    users = [
      "admin:$2a$10$K2ul0gaUotcRRqTWnq4TRu06nxRo0yyO.ky8k..vpu2MgedAFLX4K"
    ]
  }

  # JWT authentication for API/programmatic access
  jwt_auth {
    enabled = "on"
    # Secret for signing JWTs (base64, 16/24/32 bytes)
    secret = "7JQ7Ax_xJJVJa3f_xPnslXNlQHP6NBIlq7O-_jQbhxd5qiO02bcjOzeMN9eBPjaKLQSVs79myb262-JX2_QTzxxoUAbwk4HHchKbPLrhBwE3z9C1yt3Lq-GHu2_PiU6Pgopn9bJFN9su5dHS7s0SG9r1g-gqvIWOUrXc-GQHXZM="
  }
}
```

### Admin Authentication Methods

| Method | Description | Use Case |
|--------|-------------|----------|
| `basic_auth` | Username/password with bcrypt hashes | Human users accessing dashboard |
| `jwt_auth` | JWT tokens for API access | Programmatic access, CI/CD |

### Forward Auth (Optional)
```hcl
forward_auth {
  enabled = "off"
  url     = "http://auth-service:8080/verify"
  request { enabled = "on" }
  response { enabled = "on" }
}
```
Delegates authentication to an external service.

## 3. STORAGE DIRECTORIES

Defines where Agbero stores its configuration and data.

```hcl
storage {
  hosts_dir = "/Users/oleku/Library/Application Support/agbero/hosts.d"
  certs_dir = "/Users/oleku/Library/Application Support/agbero/certs.d"
  data_dir  = "/Users/oleku/Library/Application Support/agbero/data.d"
}
```

| Directory | Purpose |
|-----------|---------|
| `hosts_dir` | Host-specific routing configurations (`.hcl` files) |
| `certs_dir` | TLS certificates (managed automatically) |
| `data_dir` | Internal state (firewall bans, PID files, etc.) |

## 4. LOGGING

Controls logging behavior and destinations.

```hcl
logging {
  enabled = "on"

  # Log configuration changes on reload
  diff = "off"

  # Log level: debug, info, warn, error
  level = "info"

  # Skip logging for these path prefixes
  skip = [
    "/health",
    "/healthz",
    "/metrics",
    "/uptime",
    "/favicon.ico"
  ]

  # Include additional fields in logs
  # include = ["user_agent", "referer"]

  # File logging (local disk)
  file {
    enabled     = "on"
    path        = "/Users/oleku/Library/Application Support/agbero/logs.d/agbero.log"
    batch_size  = 500      # Number of log entries to batch
    rotate_size = 1024     # Rotate after 50MB (1024 = 50MB)
  }

  # VictoriaMetrics integration (for centralized logging)
  # victoria {
  #   enabled = "off"
  #   url = "http://localhost:9428/insert/0/prometheus/api/v1/write"
  #   batch_size = 500
  # }

  # Prometheus metrics endpoint
  # prometheus {
  #   enabled = "off"
  #   path    = "/metrics"
  # }
}
```

### Log Levels

| Level | Description |
|-------|-------------|
| `debug` | Detailed debugging information (high volume) |
| `info` | Normal operational information |
| `warn` | Warning conditions that don't affect operation |
| `error` | Error conditions that require attention |

## 5. SECURITY & FIREWALL

Global security settings and Web Application Firewall (WAF) configuration.

```hcl
security {
  enabled = "on"

  # Trusted proxy CIDRs for X-Forwarded-For resolution
  trusted_proxies = [
    "127.0.0.0/8",      # localhost
    "10.0.0.0/8",       # private networks
    "172.16.0.0/12",    # private networks
    "192.168.0.0/16",   # private networks
    "::1/128"           # IPv6 localhost
  ]

  # Path to internal auth key for service-to-service authentication
  # Generate with: agbero key init
  # internal_auth_key = "/etc/agbero/internal_auth.key"

  # Web Application Firewall
  firewall {
    enabled = "on"
    mode    = "active"   # active, verbose, monitor

    defaults {
      dynamic { action = "ban_short" }
      static  { action = "ban_hard" }
    }

    # Custom actions
    action "ban_hard" {
      mitigation = "add"
      response {
        status_code = 403
        body_template = "{\"error\": \"Access Denied\"}"
      }
    }

    action "ban_short" {
      mitigation = "add"
      response { status_code = 429 }
    }
  }
}
```

### Firewall Modes

| Mode | Description |
|------|-------------|
| `active` | Actively blocks malicious requests |
| `verbose` | Logs but doesn't block (for testing rules) |
| `monitor` | Monitors but takes no action |

## 6. TIMEOUTS & LIMITS

Global connection and request timeouts.

```hcl
timeouts {
  read        = "30s"   # Maximum duration for reading request
  write       = "60s"   # Maximum duration for writing response
  idle        = "120s"  # Maximum idle time between requests
  read_header = "5s"    # Time to read request headers
}

general {
  max_header_bytes = 1048576  # 1MB maximum header size
}
```

## 7. CLUSTERING (Gossip)

Configuration for cluster communication and distributed operation.

```hcl
gossip {
  enabled = "off"

  # Gossip protocol port (UDP and TCP)
  port = 7946

  # Secret key for encrypting gossip traffic (16, 24, or 32 bytes decoded)
  # Generate with: agbero cluster secret
  # secret_key = "b64.xVZ9k2mN8pQrS4tU6vW8xY0zA1bC3dE5fG7hI9jK="

  # Initial seed nodes to join (host:port format)
  # seeds = ["10.0.0.2:7946", "10.0.0.3:7946"]

  # TTL for cluster route entries in seconds
  # ttl = 30
}
```

### What Gets Synchronized

| Type | Description |
|------|-------------|
| Host Configs | Route definitions synced to `hosts.d/` |
| Certificates | TLS certificates and encrypted private keys |
| ACME Challenges | Let's Encrypt HTTP-01 challenge tokens |
| Node Status | Node health and draining status |

## 8. ACME / LET'S ENCRYPT

Automatic TLS certificate provisioning.

```hcl
letsencrypt {
  enabled = "on"

  # Email for registration and expiry notifications
  email = "admin@example.com"

  # Use staging CA for testing (avoids rate limits, untrusted certs)
  staging = true

  # Request short-lived certificates (for testing/ephemeral envs)
  short_lived = false
}
```

### Staging vs Production

| Environment | URL | Certificates | Use Case |
|-------------|-----|--------------|----------|
| Staging (`staging = true`) | `https://acme-staging-v02.api.letsencrypt.org/directory` | Untrusted | Testing, development |
| Production (`staging = false`) | `https://acme-v02.api.letsencrypt.org/directory` | Trusted | Production deployments |

## CLI Commands Reference

```bash
# Generate admin password hash
agbero hash -p mypassword

# Generate internal auth key
agbero key init

# Generate cluster secret
agbero cluster secret

# Validate configuration
agbero validate

# Reload configuration
agbero reload
```

## Next Steps

After configuring your global settings, proceed to [Host Configuration](./host.md) to define your routing rules and backends.
```