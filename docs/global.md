# Agbero Global Configuration (agbero.hcl)

This file is the main configuration for the Agbero proxy. Host-specific configurations belong in `hosts.d/*.hcl`.

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

---

## Understanding `enabled` Fields

Agbero uses a flexible `Enabled` type that accepts multiple formats:

| Value Type | Active Examples | Inactive Examples | Unknown |
|------------|----------------|-------------------|---------|
| Strings | `"on"`, `"true"`, `"enabled"`, `"enable"`, `"yes"` | `"off"`, `"false"`, `"disabled"`, `"disable"`, `"no"` | `"unknown"`, `"default"`, `""` |
| Booleans | `true` | `false` | - |
| Integers | `1` | `-1` | `0` |

**Examples:**
```hcl
enabled = "on"      # Active
enabled = true      # Active
enabled = 1         # Active
enabled = "off"     # Inactive
enabled = false     # Inactive
enabled = -1        # Inactive
enabled = unknown   # Use default behavior
enabled = ""        # Use default behavior
```

---

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

**Validation:**
- At least one of `http` or `https` must be configured
- Addresses must be valid `host:port` or `:port` format

---

## 2. TIMEOUTS

Global connection and request timeouts.

```hcl
timeouts {
  enabled     = "on"
  read        = "30s"   # Maximum duration for reading request
  write       = "60s"   # Maximum duration for writing response
  idle        = "120s"  # Maximum idle time between requests
  read_header = "5s"    # Time to read request headers
}
```

**Defaults:**
- `read`: 10s
- `write`: 30s
- `idle`: 120s
- `read_header`: 5s

**Validation:** All timeouts must be non-negative when enabled.

---

## 3. STORAGE DIRECTORIES

Defines where Agbero stores its configuration and data. Paths are resolved relative to the config file unless absolute.

```hcl
storage {
  hosts_dir = "hosts.d"        # Relative to config file
  certs_dir = "/etc/agbero/certs.d"  # Absolute path
  data_dir  = "data.d"
  work_dir  = "work.d"
}
```

| Directory | Purpose |
|-----------|---------|
| `hosts_dir` | Host-specific routing configurations (`.hcl` files) |
| `certs_dir` | TLS certificates (managed automatically) |
| `data_dir` | Internal state (firewall DB, PID files, telemetry DB) |
| `work_dir` | Working directory for Git deployments |

---

## 4. GENERAL SETTINGS

```hcl
general {
  max_header_bytes = 1048576  # 1MB maximum header size
}
```

- **`max_header_bytes`**: Maximum size of request headers (default: 1MB)

---

## 5. ADMIN INTERFACE

The administrative dashboard and API for monitoring and managing Agbero.

```hcl
admin {
  # Enable admin UI and API endpoints
  enabled = "on"

  # Admin interface bind address
  address = ":9090"

  # Enable pprof debugging endpoints (security risk in production)
  pprof = "off"

  # Restrict admin access to specific IPs/CIDRs
  allowed_ips = ["127.0.0.1", "::1", "192.168.1.0/24"]

  # Basic authentication for the /login endpoint
  basic_auth {
    enabled = "on"
    # Format: "username:bcrypt_hash"
    users = [
      "admin:$2a$10$K2ul0gaUotcRRqTWnq4TRu06nxRo0yyO.ky8k..vpu2MgedAFLX4K"
    ]
    realm = "Admin Area"  # Optional
  }

  # JWT authentication for API/programmatic access
  jwt_auth {
    enabled = "on"
    # Secret for signing JWTs (can be raw string, env var, or base64)
    secret = "${env.ADMIN_JWT_SECRET}"
    claims_to_headers = {  # Optional: map claims to headers
      "sub" = "X-User-ID"
    }
    issuer = "agbero-admin"   # Optional: validate issuer
    audience = "api"          # Optional: validate audience
  }

  # Forward authentication (delegate to external service)
  forward_auth {
    enabled = "off"
    name    = "admin-auth"    # Optional identifier
    url     = "http://auth:9000/verify"
    on_failure = "deny"       # "allow" or "deny"
    timeout = "5s"

    tls {                     # Optional: mTLS configuration
      enabled = "off"
      insecure_skip_verify = false
      client_cert = "${env.CLIENT_CERT}"
      client_key  = "${env.CLIENT_KEY}"
      ca = "${env.CA_CERT}"
    }

    request {
      enabled = "on"
      headers = ["Authorization", "Cookie"]
      forward_method = true
      forward_uri = true
      forward_ip = true
      body_mode = "none"      # "none", "metadata", or "limited"
      max_body = 65536        # For "limited" mode
    }

    response {
      enabled = "on"
      copy_headers = ["X-User", "X-Roles"]
      cache_ttl = "1m"        # Cache successful auth decisions
    }
  }

  # OAuth authentication (not typically used for admin)
  o_auth {
    enabled = "off"
  }
}
```

### Admin Authentication Priority

When multiple auth methods are enabled, Agbero uses them in this order:
1. IP allowlist (always applied first)
2. JWT auth (if enabled)
3. Basic auth (if enabled and JWT not used)

---

## 6. PPROF DEBUGGING

Separate pprof listener with no middleware for performance profiling.

```hcl
pprof {
  enabled = "off"
  bind    = "localhost:6060"  # Bind address for pprof
}
```

**Warning:** This exposes profiling endpoints with no authentication. Bind to loopback in production.

---

## 7. API CONFIGURATION

Internal API for cluster management.

```hcl
api {
  enabled = "off"
  address = ":9091"
  allowed_ips = ["127.0.0.1", "10.0.0.0/8"]
}
```

---

## 8. LOGGING

Controls logging behavior and destinations.

```hcl
logging {
  enabled = "on"

  # Log level: debug, info, warn, error
  level = "info"

  # Log configuration changes on reload
  diff = "off"

  # Deduplicate repeated log entries
  deduplicate = "on"

  # Truncate long fields (like user agent)
  truncate = "on"

  # Enable bot detection in logs
  bot_checker = "on"

  # Skip logging for these path prefixes
  skip = [
    "/health",
    "/healthz",
    "/metrics",
    "/uptime",
    "/favicon.ico"
  ]

  # File logging (local disk)
  file {
    enabled     = "on"
    path        = "logs.d/agbero.log"  # Relative to config or absolute
    batch_size  = 500      # Number of log entries to batch
    rotate_size = 52428800 # Rotate after 50MB (bytes)
  }

  # VictoriaMetrics integration (for centralized logging)
  victoria {
    enabled    = "off"
    url        = "http://victoria:8428/api/v1/write"
    batch_size = 500
  }

  # Prometheus metrics endpoint
  prometheus {
    enabled = "on"
    path    = "/metrics"   # Default: /metrics
  }
}
```

### Log Levels

| Level | Description |
|-------|-------------|
| `debug` | Detailed debugging information (high volume) |
| `info` | Normal operational information |
| `warn` | Warning conditions that don't affect operation |
| `error` | Error conditions that require attention |

---

## 9. SECURITY & FIREWALL

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
  # Generate with: agbero secret key init
  internal_auth_key = "/etc/agbero/certs.d/internal_auth.key"

  # Web Application Firewall
  firewall {
    enabled = "on"
    mode    = "active"   # active, verbose, monitor

    # Whether to inspect request bodies
    inspect_body = true
    max_inspect_bytes = 8192
    inspect_content_types = [
      "application/json",
      "application/xml",
      "application/x-www-form-urlencoded",
      "text/plain"
    ]

    # Default actions for different rule types
    defaults {
      dynamic {
        action = "ban"
        duration = "24h"
      }
      static {
        action = "deny"
        duration = "0"  # Permanent
      }
    }

    # Custom actions
    action "ban" {
      mitigation = "add"  # "add" adds to ban store
      response {
        enabled = true
        status_code = 403
        content_type = "application/json"
        body_template = "{\"error\": \"Access Denied\"}"
        headers = {
          "X-Block-Reason" = "WAF"
        }
      }
    }

    action "rate-limit" {
      mitigation = "add"
      response {
        status_code = 429
        body_template = "Rate limit exceeded"
      }
    }

    # Rules
    rule "block-scanners" {
      name        = "block-scanners"
      type        = "static"      # static, dynamic, whitelist
      action      = "ban"
      priority    = 10

      match {
        enabled = true
        any {
          location = "path"
          pattern = ".*\\.(php|asp|aspx|jsp)$"
        }
        any {
          location = "header"
          key = "User-Agent"
          pattern = "(?i)(nikto|nmap|sqlmap|acunetix)"
        }
      }
    }

    rule "rate-limit-abuse" {
      name   = "rate-limit-abuse"
      type   = "dynamic"
      action = "rate-limit"
      
      match {
        threshold {
          enabled = true
          count   = 100
          window  = "1m"
          track_by = "ip"
        }
      }
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

---

## 10. RATE LIMITS

Global rate limiting policies and rules.

```hcl
rate_limits {
  enabled = "on"
  ttl     = "30m"        # Cache TTL for rate limit entries
  max_entries = 100000   # Maximum entries in cache

  # Named policies that can be referenced by routes
  policies = [
    {
      name     = "api-strict"
      requests = 10
      window   = "1m"
      burst    = 15
      key      = "ip"
    },
    {
      name     = "api-lenient"
      requests = 1000
      window   = "1h"
      burst    = 200
      key      = "header:X-API-Key"
    }
  ]

  # Global rules applied to all requests
  rules = [
    {
      name     = "global-limit"
      enabled  = "on"
      prefixes = ["/api/"]
      methods  = ["GET", "POST"]
      requests = 100
      window   = "1m"
      burst    = 150
      key      = "ip"
    }
  ]
}
```

### Rate Limit Keys

| Key | Description |
|-----|-------------|
| `ip` | Client IP address |
| `header:Name` | Value of specified header |
| `cookie:Name` | Value of specified cookie |
| `query:Name` | Value of query parameter |

---

## 11. CLUSTERING (Gossip)

Configuration for cluster communication and distributed operation.

```hcl
gossip {
  enabled = "off"

  # Gossip protocol port (UDP and TCP)
  port = 7946

  # Secret key for encrypting gossip traffic (16, 24, or 32 bytes)
  # Generate with: agbero secret cluster
  secret_key = "b64.xVZ9k2mN8pQrS4tU6vW8xY0zA1bC3dE5fG7hI9jK="

  # Initial seed nodes to join (host:port format)
  seeds = ["10.0.0.2:7946", "10.0.0.3:7946"]

  # TTL for cluster route entries in seconds
  ttl = 30

  # Distributed shared state for rate limiting and firewalls
  shared_state {
    enabled = "off"
    driver  = "redis"   # "memory" or "redis"

    redis {
      host       = "localhost"
      port       = 6379
      password   = "${env.REDIS_PASS}"
      db         = 0
      key_prefix = "agbero:state:"
    }
  }
}
```

### What Gets Synchronized

| Type | Protocol | Description |
|------|----------|-------------|
| Host Configs | TCP | Route definitions synced to `hosts.d/` |
| Certificates | TCP | TLS certificates and encrypted private keys |
| ACME Challenges | UDP | Let's Encrypt HTTP-01 challenge tokens |
| Node Status | UDP | Node health and draining status |
| Distributed Locks | UDP | Coordination primitives |

---

## 12. ACME / LET'S ENCRYPT

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

  # Pebble integration for testing (development only)
  pebble {
    enabled = false
    url = "https://localhost:14000/dir"
    insecure = true
    chall_srv = "http://localhost:8055"
    mgmt_server = "http://localhost:8055"
  }
}
```

### Staging vs Production

| Environment | URL | Certificates | Use Case |
|-------------|-----|--------------|----------|
| Staging (`staging = true`) | `https://acme-staging-v02.api.letsencrypt.org/directory` | Untrusted | Testing, development |
| Production (`staging = false`) | `https://acme-v02.api.letsencrypt.org/directory` | Trusted | Production deployments |

---

## 13. FALLBACK RESPONSES

Default responses when no backend is available.

```hcl
fallback {
  enabled = "off"
  type    = "static"      # static, redirect, proxy
  status_code = 503
  body = "Service Unavailable"
  content_type = "application/json"
  # redirect_url = "https://maintenance.example.com"  # For type=redirect
  # proxy_url = "http://backup:8080"                  # For type=proxy
  cache_ttl = 0
}
```

---

## 14. ERROR PAGES

Custom error pages for HTTP error codes.

```hcl
error_pages {
  pages = {
    "404" = "/etc/agbero/errors/404.html"
    "503" = "/etc/agbero/errors/503.html"
  }
  default = "/etc/agbero/errors/error.html"
}
```

---

## 15. TELEMETRY

Built-in time-series performance collector.

```hcl
telemetry {
  enabled = "off"  # Off by default
}
```

When enabled, samples key metrics every 60 seconds and retains up to 24 hours of history. Accessible via protected admin endpoint `/telemetry/history`.

---

## CLI Commands Reference

```bash
# Generate admin password hash
agbero secret hash --password mypassword

# Generate internal auth key
agbero secret key init

# Generate cluster secret
agbero secret cluster

# Validate configuration
agbero config validate

# Reload configuration
sudo agbero config reload
```

## Environment Variables in Configuration

Agbero supports environment variable interpolation in HCL:

```hcl
secret = "${env.JWT_SECRET}"
path   = "${env.CONFIG_DIR}/certs"
```

Also supports base64-encoded values:
```hcl
secret_key = "b64.${env.BASE64_SECRET}"
```

## Next Steps

After configuring your global settings, proceed to [Host Configuration](./host.md) to define your routing rules and backends.