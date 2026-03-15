# Agbero Global Configuration (agbero.hcl)

This is the main configuration file for Agbero. It controls global settings like binding addresses, security, logging, and clustering. Host-specific routing rules belong in separate files under `hosts.d/`.

## Configuration Template

When you run `agbero init`, this is the template that gets created:

```hcl
# =============================================================================
# AGBERO - GLOBAL CONFIGURATION (agbero.hcl)
# =============================================================================
# This file is the main configuration for the agbero proxy.
# Host-specific configurations belong in hosts.d/*.hcl
# =============================================================================

# Configuration schema version - must match binary
version = 1

# Enable development mode: debug logging, verbose errors, relaxed TLS
# WARNING: Disable for production
development = true

# -------------------------------------------------------------
# BINDING ADDRESSES
# -------------------------------------------------------------
bind {
  # HTTP listeners (plain text, usually redirects to HTTPS)
  http = [":80"]

  # HTTPS/HTTP3 listeners (TLS required)
  https = [":443"]

  # Automatically redirect HTTP -> HTTPS
  redirect = on
}

# -------------------------------------------------------------
# ADMIN INTERFACE
# -------------------------------------------------------------
admin {
  # Enable admin UI and API endpoints
  enabled = on

  # Admin interface bind address
  address = ":9090"

  # Restrict admin access to specific IPs/CIDRs
  allowed_ips = ["127.0.0.1", "::1"]

  # Enable pprof debugging endpoints (security risk in prod)
  pprof = off

  # ---------------------------------------------------------
  # BASIC AUTH (for /login endpoint)
  # ---------------------------------------------------------
  basic_auth {
    enabled = on
    # Format: "username:bcrypt_hash"
    users = [
      "admin:$2a$10$K2ul0gaUotcRRqTWnq4TRu06nxRo0yyO.ky8k..vpu2MgedAFLX4K"
    ]
  }

  # ---------------------------------------------------------
  # JWT AUTH (for API/programmatic access)
  # ---------------------------------------------------------
  jwt_auth {
    enabled = on
    # Secret for signing JWTs (base64, 16/24/32 bytes)
    secret = "7JQ7Ax_xJJVJa3f_xPnslXNlQHP6NBIlq7O-_jQbhxd5qiO02bcjOzeMN9eBPjaKLQSVs79myb262-JX2_QTzxxoUAbwk4HHchKbPLrhBwE3z9C1yt3Lq-GHu2_PiU6Pgopn9bJFN9su5dHS7s0SG9r1g-gqvIWOUrXc-GQHXZM="
  }
}

# -------------------------------------------------------------
# STORAGE DIRECTORIES
# -------------------------------------------------------------
storage {
  hosts_dir = "/Users/oleku/Library/Application Support/agbero/hosts.d"
  certs_dir = "/Users/oleku/Library/Application Support/agbero/certs.d"
  data_dir  = "/Users/oleku/Library/Application Support/agbero/data.d"
  work_dir  = "/Users/oleku/Library/Application Support/agbero/work.d"  # Git deployments
}

# -------------------------------------------------------------
# LOGGING
# -------------------------------------------------------------
logging {
  enabled = on

  # Log configuration changes on reload
  diff = off

  # Deduplicate repeated log messages
  deduplicate = on

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

  # ---------------------------------------------------------
  # FILE LOGGING
  # ---------------------------------------------------------
  file {
    enabled     = on
    path        = "/Users/oleku/Library/Application Support/agbero/logs.d/agbero.log"
    batch_size  = 500      # Number of log entries to batch
    rotate_size = 50       # Rotate after 50MB
  }

  # ---------------------------------------------------------
  # VICTORIALOGS INTEGRATION
  # ---------------------------------------------------------
  victoria {
    enabled = off
    url = "http://localhost:9428/insert/0/prometheus/api/v1/write"
    batch_size = 500
  }

  # ---------------------------------------------------------
  # PROMETHEUS METRICS ENDPOINT
  # ---------------------------------------------------------
  prometheus {
    enabled = off
    path    = "/metrics"
  }
}

# -------------------------------------------------------------
# SECURITY & FIREWALL
# -------------------------------------------------------------
security {
  enabled = on

  # Trusted proxy CIDRs for X-Forwarded-For resolution
  trusted_proxies = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "::1/128"
  ]

  # Path to internal auth key for service-to-service authentication
  # Generate with: agbero secret key init
  # internal_auth_key = "/etc/agbero/internal_auth.key"

  # ---------------------------------------------------------
  # APPLICATION FIREWALL / WAF
  # ---------------------------------------------------------
  firewall {
    enabled = on
    mode    = "active"  # active, verbose, monitor

    defaults {
      dynamic { action = "ban_short" }
      static  { action = "ban_hard" }
    }

    # Define actions referenced above
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

# -------------------------------------------------------------
# RATE LIMITING
# -------------------------------------------------------------
rate_limits {
  enabled = on
  
  # Global cache settings
  ttl         = "30m"        # How long to track counters
  max_entries = 100000        # Maximum entries in cache

  # Named policies that routes can reference
  policy "api-strict" {
    requests = 10
    window   = "1m"
    burst    = 15
    key      = "ip"
  }

  policy "api-lenient" {
    requests = 1000
    window   = "1h"
    burst    = 200
    key      = "header:X-API-Key"
  }

  # Default rules applied to all routes
  rule "global-default" {
    enabled   = on
    prefixes  = ["/api/"]
    requests  = 100
    window    = "1m"
    key       = "ip"
  }
}

# -------------------------------------------------------------
# API SERVER (Internal API)
# -------------------------------------------------------------
api {
  enabled = off
  address = ":9091"
  allowed_ips = ["127.0.0.1", "10.0.0.0/8"]
}

# -------------------------------------------------------------
# TIMEOUTS & LIMITS
# -------------------------------------------------------------
timeouts {
  enabled     = on
  read        = "30s"
  write       = "60s"
  idle        = "120s"
  read_header = "5s"
}

general {
  max_header_bytes = 1048576  # 1MB
}

# -------------------------------------------------------------
# CLUSTERING (Gossip)
# -------------------------------------------------------------
gossip {
  enabled = off

  # Gossip protocol port (default: 7946)
  port = 7946

  # Secret key for encrypting gossip traffic (16, 24, or 32 bytes decoded)
  # Generate with: agbero secret cluster
  # secret_key = "b64.xVZ9k2mN8pQrS4tU6vW8xY0zA1bC3dE5fG7hI9jK="

  # Initial seed nodes to join (host:port format)
  # seeds = ["10.0.0.2:7946", "10.0.0.3:7946"]

  # TTL for cluster route entries in seconds
  ttl = 30

  # Distributed state for rate limiting & firewall
  shared_state {
    enabled = off
    driver  = "redis"  # memory or redis
    redis {
      host       = "localhost"
      port       = 6379
      password   = "${env.REDIS_PASS}"
      db         = 0
      key_prefix = "agbero:state:"
    }
  }
}

# -------------------------------------------------------------
# ACME / LET'S ENCRYPT
# -------------------------------------------------------------
letsencrypt {
  enabled = on

  # Email for registration and expiry notifications
  email = "admin@example.com"

  # Use staging CA for testing (avoids rate limits, untrusted certs)
  staging = true

  # Request short-lived certificates (for testing/ephemeral envs)
  short_lived = false
}

# -------------------------------------------------------------
# GLOBAL FALLBACK RESPONSES
# -------------------------------------------------------------
fallback {
  enabled = off
  type    = "static"      # static, redirect, proxy
  status_code = 503
  body = "{\"error\":\"Service Unavailable\"}"
  content_type = "application/json"
  # redirect_url = "https://backup.example.com"
  # proxy_url = "http://backup:8080"
  cache_ttl = 0  # seconds
}

# -------------------------------------------------------------
# GLOBAL ERROR PAGES
# -------------------------------------------------------------
error_pages {
  pages = {
    "404" = "/var/www/errors/404.html",
    "500" = "/var/www/errors/500.html",
    "502" = "/var/www/errors/502.html",
    "503" = "/var/www/errors/503.html"
  }
  default = "/var/www/errors/default.html"
}
```

## Configuration Reference

### Understanding `enabled` Fields

Agbero uses a flexible `Enabled` type that accepts multiple formats:

| Value Type | Active Examples | Inactive Examples | Auto-detect |
|------------|----------------|-------------------|-------------|
| Strings | `"on"`, `"true"`, `"enabled"`, `"enable"`, `"yes"` | `"off"`, `"false"`, `"disabled"`, `"disable"`, `"no"` | `"unknown"`, `"default"`, `""` |
| Booleans | `true` | `false` | - |
| Integers | `1` | `-1` | `0` |

**Examples:**
```hcl
enabled = on        # Active
enabled = true      # Active
enabled = 1         # Active
enabled = off       # Inactive
enabled = unknown   # Use default behavior
enabled = ""        # Use default behavior
```

### Dynamic Values (`env.` and `b64.`)

Agbero supports dynamic value resolution:

```hcl
# Environment variables
secret = "${env.DATABASE_PASSWORD}"     # Shell expansion
secret = "env.DATABASE_PASSWORD"         # Direct env reference

# Base64-encoded values (for binary data)
private_key = "b64.LS0tLS1CRUdJTiBSU0EgUFJJVkFURS...="

# Mixed
password = "b64.${env.B64_PASSWORD}"     # Combined
```

### Hot Reload Support

The following sections support hot reload (SIGHUP or `agbero config reload`):

| Block | Reload Support | Notes |
|-------|---------------|-------|
| `bind` | ❌ No | Requires restart |
| `admin` | ❌ No | Requires restart |
| `api` | ❌ No | Requires restart |
| `storage` | ❌ No | Requires restart |
| `logging` | ✅ Yes | Most settings |
| `security` | ✅ Yes | Firewall rules |
| `rate_limits` | ✅ Yes | Policies and rules |
| `gossip` | ❌ No | Requires restart |
| `letsencrypt` | ✅ Yes | Email, staging |
| `fallback` | ✅ Yes | |
| `error_pages` | ✅ Yes | |
| `timeouts` | ❌ No | Requires restart |
| `general` | ❌ No | Requires restart |

## Block Reference

### `bind` - Binding Addresses

Controls which ports and interfaces Agbero listens on.

```hcl
bind {
  http    = [":80", ":8080"]        # HTTP listeners
  https   = [":443", ":8443"]        # HTTPS/HTTP3 listeners
  redirect = on                       # Auto HTTP → HTTPS redirect
}
```

- **`http`**: List of addresses for HTTP connections
- **`https`**: List of addresses for HTTPS and HTTP/3 connections
- **`redirect`**: When `on`, HTTP requests redirect to HTTPS

### `admin` - Admin Interface

The administrative dashboard and API.

```hcl
admin {
  enabled     = on
  address     = ":9090"
  allowed_ips = ["127.0.0.1", "10.0.0.0/8"]
  pprof       = off

  basic_auth {
    enabled = on
    users   = ["admin:$2a$10$..."]
  }

  jwt_auth {
    enabled = on
    secret  = "b64.7JQ7Ax_xJJVJa3f_xPnslXNl..."
  }
}
```

| Field | Description |
|-------|-------------|
| `enabled` | Enable admin interface |
| `address` | Bind address (e.g., ":9090") |
| `allowed_ips` | Restrict access to IPs/CIDRs |
| `pprof` | Enable Go pprof debugging endpoints |
| `basic_auth` | Username/password authentication |
| `jwt_auth` | JWT token authentication |

### `storage` - Directory Paths

Defines where Agbero stores data.

```hcl
storage {
  hosts_dir = "/var/lib/agbero/hosts.d"   # Host configurations
  certs_dir = "/var/lib/agbero/certs.d"   # TLS certificates
  data_dir  = "/var/lib/agbero/data.d"    # Internal state (PID, firewall)
  work_dir  = "/var/lib/agbero/work.d"    # Git deployments (Cook)
}
```

| Directory | Purpose |
|-----------|---------|
| `hosts_dir` | Host-specific routing configs (`.hcl` files) |
| `certs_dir` | TLS certificates (auto-managed) |
| `data_dir` | Internal state (firewall bans, PID files) |
| `work_dir` | Git deployment working directory |

### `logging` - Logging Configuration

Controls logging behavior and destinations.

```hcl
logging {
  enabled     = on
  diff        = off      # Log config changes on reload
  deduplicate = on       # Deduplicate repeated messages
  level       = "info"   # debug, info, warn, error
  
  skip = [
    "/health",
    "/metrics"
  ]
  
  # include = ["user_agent", "referer"]

  file {
    enabled     = on
    path        = "/var/log/agbero/agbero.log"
    batch_size  = 500
    rotate_size = 50    # MB
  }

  victoria {
    enabled = off
    url     = "http://victoria:8428/api/v1/write"
    batch_size = 500
  }

  prometheus {
    enabled = off
    path    = "/metrics"
  }
}
```

### `security` - Security & Firewall

Global security settings and WAF configuration.

```hcl
security {
  enabled = on
  
  trusted_proxies = [
    "10.0.0.0/8",
    "172.16.0.0/12"
  ]
  
  internal_auth_key = "/etc/agbero/internal_auth.key"

  firewall {
    enabled = on
    mode    = "active"  # active, verbose, monitor
    
    defaults {
      dynamic { action = "ban_short" }
      static  { action = "ban_hard" }
    }
    
    action "ban_hard" {
      mitigation = "add"
      response {
        status_code = 403
        body_template = "{\"error\": \"Access Denied\"}"
      }
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `trusted_proxies` | CIDRs trusted for `X-Forwarded-For` |
| `internal_auth_key` | Path to Ed25519 private key |
| `firewall.mode` | `active` (block), `verbose` (log only), `monitor` (passive) |
| `firewall.defaults` | Default actions for dynamic/static rules |
| `firewall.action` | Named action definitions |

### `rate_limits` - Global Rate Limiting

Define rate limit policies and default rules.

```hcl
rate_limits {
  enabled = on
  ttl         = "30m"
  max_entries = 100000

  policy "api-strict" {
    requests = 10
    window   = "1m"
    burst    = 15
    key      = "ip"
  }

  rule "global-default" {
    enabled  = on
    prefixes = ["/api/"]
    requests = 100
    window   = "1m"
    key      = "ip"
  }
}
```

| Field | Description |
|-------|-------------|
| `ttl` | How long to track counters |
| `max_entries` | Maximum entries in cache |
| `policy` | Named policy routes can reference |
| `rule` | Default rule applied to matching paths |

### `api` - Internal API Server

Separate API server for internal operations.

```hcl
api {
  enabled = off
  address = ":9091"
  allowed_ips = ["127.0.0.1", "10.0.0.0/8"]
}
```

### `timeouts` - Connection Timeouts

```hcl
timeouts {
  enabled     = on
  read        = "30s"
  write       = "60s"
  idle        = "120s"
  read_header = "5s"
}
```

### `gossip` - Cluster Configuration

```hcl
gossip {
  enabled = off
  port    = 7946
  # secret_key = "b64.xVZ9k2mN8pQrS4tU6vW8xY0zA1bC3dE5fG7hI9jK="
  # seeds = ["10.0.0.2:7946"]
  ttl = 30

  shared_state {
    enabled = off
    driver  = "redis"
    redis {
      host     = "localhost"
      port     = 6379
      password = "${env.REDIS_PASS}"
      db       = 0
      key_prefix = "agbero:state:"
    }
  }
}
```

### `letsencrypt` - Automatic TLS

```hcl
letsencrypt {
  enabled = on
  email   = "admin@example.com"
  staging = true        # Use staging CA (untrusted certs)
  short_lived = false   # Request short-lived certs
}
```

### `fallback` - Global Fallback

```hcl
fallback {
  enabled = off
  type    = "static"      # static, redirect, proxy
  status_code = 503
  body = "{\"error\":\"Service Unavailable\"}"
  content_type = "application/json"
  # redirect_url = "https://backup.example.com"
  # proxy_url = "http://backup:8080"
  cache_ttl = 0
}
```

### `error_pages` - Custom Error Pages

```hcl
error_pages {
  pages = {
    "404" = "/var/www/errors/404.html",
    "500" = "/var/www/errors/500.html"
  }
  default = "/var/www/errors/default.html"
}
```

### `general` - General Settings

```hcl
general {
  max_header_bytes = 1048576  # 1MB maximum header size
}
```

## Validation Rules

| Field | Validation |
|-------|------------|
| `port` | Must be between 1-65535 |
| `address` | Must be valid host:port or :port |
| `allowed_ips` | Must be valid IP or CIDR |
| `trusted_proxies` | Must be valid IP or CIDR |
| `cert_file` | Must be absolute path |
| `key_file` | Must be absolute path |

## Next Steps

- [**Host Configuration**](./host.md) - Define routes and backends
- [**Advanced Guide**](./advance.md) - Clustering, Git Deployments, WASM
- [**CLI Reference**](./command.md) - Command-line documentation
```