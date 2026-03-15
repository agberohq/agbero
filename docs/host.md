# Agbero Host Configuration Guide

Host configuration files in `hosts.d/*.hcl` define your domains and routing rules. Each file can define one or more domains and their associated routes.

## Directory Structure & Navigation

Before writing host configurations, you need to understand where they live. Agbero organizes everything in a simple directory structure:

```
agbero-home/
├── agbero.hcl              # Main configuration (created by `agbero init`)
├── hosts.d/                 # Your host configurations go here
│   ├── admin.hcl
│   ├── api.hcl
│   ├── blog.hcl
│   └── ...
├── certs.d/                 # TLS certificates (auto-managed)
├── data.d/                  # Internal state (firewall bans, PID)
├── logs.d/                   # Log files
└── work.d/                   # Git deployment working directories
```

### Finding Your Agbero Home

After installation, your Agbero home location depends on how you installed:

**User installation (no sudo):**
```
~/.config/agbero/              # Linux/macOS
%APPDATA%\agbero\              # Windows
```

**System installation (with sudo):**
```
/etc/agbero/                    # Linux
/Library/Application Support/agbero/  # macOS
C:\ProgramData\agbero\          # Windows
```

### The `agbero home` Command

The easiest way to navigate is using the `home` command:

```bash
# Show your Agbero home directory path
agbero home

# Open a shell directly in your Agbero home
agbero home @

# Jump to specific directories
agbero home hosts          # Show hosts.d path
agbero home hosts @        # Open shell in hosts.d
cd $(agbero home hosts)    # cd to hosts.d

agbero home certs @        # Open shell in certs.d
agbero home logs @         # Open shell in logs.d
agbero home work @         # Open shell in work.d

# View or edit config file
agbero home config         # Show config file path
agbero home config @cat    # View config
agbero home config @vim    # Edit config with vim
agbero home config @code   # Edit with VS Code
```

### Creating Your First Host File

Now that you know where files go, creating a host configuration is simple:

```bash
# Navigate to hosts.d
cd $(agbero home hosts)

# Create a new host file
vim mysite.hcl
# or
code mysite.hcl
# or use the interactive helper
agbero host add
```

Your `hosts.d` directory will look something like this after adding a few hosts:

```
hosts.d/
├── admin.hcl      # Admin panel
├── api.hcl        # API backend
├── blog.hcl       # Static blog
└── cook.hcl       # Git-deployed site
```

### How Agbero Finds Hosts

Agbero automatically watches `hosts.d` and all its subdirectories. You can organize files any way you like:

```
hosts.d/
├── production/
│   ├── api.hcl
│   └── web.hcl
├── staging/
│   └── api.hcl
└── local/
    └── dev.hcl
```

Any `.hcl` file found (recursively) is loaded. Changes are picked up automatically - no restart needed!

---

## Quick Start: 60% of Use Cases Covered

### 1. Static Website (Local Files)

Serve a static website from your local filesystem:

```hcl
# hosts.d/mysite.hcl
domains = ["localhost", "mysite.localhost"]

route "/" {
  web {
    root    = "~/www/mywebsite"  # Path to your files
    listing = true                # Show directory listing if no index
    index   = "index.html"        # Default index file

    # Optional: PHP support
    # php {
    #   address = "127.0.0.1:9000"
    #   index   = "index.php"
    # }
  }
}
```

**What this does:**
- Serves files from `~/www/mywebsite`
- Auto-generates directory listings
- Works immediately with zero additional config
- Access at `http://localhost` or `http://mysite.localhost`

### 2. Git-Deployed Website (Cook)

Serve a website that automatically updates from Git:

```hcl
# hosts.d/cook.hcl
domains = ["cook.localhost"]

route "/" {
  web {
    root    = "/Users/oleku/www/olekukonko/sample.local"
    listing = true
    index   = "README.md"

    # Render Markdown files as HTML
    markdown {
      enabled = on
      view    = "normal"  # 'normal' or 'browse'
    }

    # Auto-deploy from Git
    git {
      enabled  = on
      id       = "sample_app"
      url      = "https://github.com/olekukonko/sample.git"
      branch   = "main"
      secret   = ""                    # Webhook secret (optional)
      interval = "1m"                   # Poll for changes
    }
  }
}
```

**What this does:**
- Clones your Git repository
- Automatically pulls updates every minute
- Renders Markdown files as HTML
- Zero-downtime atomic deployments
- Access at `http://cook.localhost`

### 3. Reverse Proxy (Load Balancer)

Proxy to backend servers with load balancing:

```hcl
# hosts.d/proxy.hcl
domains = ["example.localhost"]

route "/*" {
  # Health checks ensure only healthy backends receive traffic
  health_check {
    path = "/health"
  }

  backend {
    strategy = "round_robin"  # Distribute traffic evenly

    server {
      address = "http://localhost:6060"
      weight  = 1
    }

    server {
      address = "http://localhost:6061"
      weight  = 1
    }
  }
}
```

**What this does:**
- Load balances between two backend servers
- Automatically removes unhealthy servers
- Zero-config hot reload when backends change
- Access at `http://example.localhost`

---

These three patterns cover **50-60% of common use cases**. The rest of this guide covers every configuration option in detail.

## Host Block Reference

### Basic Structure

```hcl
# hosts.d/example.hcl
domains = ["example.com", "api.example.com"]  # Required: at least one domain

# Optional: Override global bind ports
bind = ["8080", "8443"]

# Optional: Custom 404 page for this host
not_found_page = "/var/www/errors/404.html"

# Optional: Enable compression at host level
compression = true

# Optional: Host-level TLS configuration
tls {
  # See TLS section below
}

# Optional: Host-level limits
limits {
  max_body_size = 10485760  # 10MB
}

# Optional: Host-level headers
headers {
  # See Headers section below
}

# Optional: Host-level error pages
error_pages {
  pages = {
    "404" = "/var/www/errors/404.html"
  }
}

# HTTP routes (L7)
route "/" {
  # ... route configuration
}

# TCP proxies (L4)
proxy "postgres" {
  # ... proxy configuration
}
```

### Host-Level Fields

| Field | Description | Example |
|-------|-------------|---------|
| `domains` | List of domains this host handles (required) | `["example.com", "api.example.com"]` |
| `bind` | Override global bind ports for this host | `["8080", "8443"]` |
| `not_found_page` | Custom 404 page path | `"/var/www/errors/404.html"` |
| `compression` | Enable compression at host level | `true` |
| `tls` | TLS configuration block | See TLS section |
| `limits` | Host-level limits | See Limits section |
| `headers` | Host-level headers | See Headers section |
| `error_pages` | Host-level error pages | See Error Pages section |
| `routes` | HTTP route definitions | Multiple `route` blocks |
| `proxies` | TCP proxy definitions | Multiple `proxy` blocks |

## Route Types

### 1. Web Routes (Static Files)

Serve static files, PHP applications, or Git-deployed sites.

```hcl
route "/" {
  web {
    # Basic static file serving
    root    = "/var/www/html"
    listing = true          # Show directory listing
    index   = "index.html"  # Default index file
    spa     = true          # SPA mode - serve index.html for all routes

    # PHP FastCGI support
    php {
      enabled = true
      address = "127.0.0.1:9000"  # or "unix:/var/run/php/php-fpm.sock"
      index   = "index.php"
    }

    # Git deployment (Cook)
    git {
      enabled  = true
      id       = "frontend_app"
      url      = "https://github.com/org/repo.git"
      branch   = "main"
      sub_dir  = "dist"              # Serve from subdirectory
      interval = "5m"                 # Poll for changes
      secret   = "${env.WEBHOOK_SECRET}"
      
      auth {
        type = "ssh-key"              # basic, ssh-key, ssh-agent
        ssh_key = "${b64.PRIVATE_KEY}"
      }
    }

    # Markdown rendering
    markdown {
      enabled    = true
      unsafe     = false               # Allow unsafe HTML
      toc        = true                # Generate table of contents
      view       = "browse"             # 'normal' or 'browse'
      template   = "custom.html"        # Custom template
      
      highlight {
        enabled = true
        theme   = "github"              # Syntax highlighting theme
      }
      
      extensions = ["table", "footnote", "tasklist"]
    }
  }
}
```

#### Web Block Fields

| Field | Description | Default |
|-------|-------------|---------|
| `root` | Root directory to serve | Required |
| `listing` | Enable directory listing | `false` |
| `index` | Default index file | `"index.html"` |
| `spa` | SPA mode (serve index.html for all routes) | `false` |
| `php` | PHP FastCGI configuration | Optional |
| `git` | Git deployment configuration | Optional |
| `markdown` | Markdown rendering configuration | Optional |

### 2. Proxy Routes (Reverse Proxy)

Proxy HTTP/HTTPS traffic to backend servers.

```hcl
route "/api" {
  # Path manipulation
  strip_prefixes = ["/api", "/v1"]      # Remove prefixes before forwarding
  
  rewrite {
    pattern = "^/v1/users/(.*)$"
    target  = "/users/$1?version=v1"
  }

  # IP restrictions
  allowed_ips = ["10.0.0.0/8", "192.168.1.0/24"]

  # Backend configuration
  backend {
    enabled  = true
    strategy = "round_robin"  # Load balancing strategy
    keys = ["cookie:session", "ip"]  # For sticky sessions/consistent hashing

    server {
      address = "http://backend-1:8080"
      weight  = 10
      
      # Request routing criteria
      criteria {
        source_ips = ["10.0.0.0/8"]
        headers = {
          "X-Region" = "us-east"
        }
      }
      
      # Streaming optimizations (WebSockets, SSE)
      streaming {
        enabled        = true
        flush_interval = "100ms"
      }
      
      max_connections = 1000
    }

    server {
      address = "http://backend-2:8080"
      weight  = 5
    }
  }

  # Health checking
  health_check {
    enabled   = true
    path      = "/health"
    method    = "GET"
    interval  = "10s"
    timeout   = "5s"
    threshold = 3
    
    headers = {
      "X-Health-Check" = "true"
    }
    
    expected_status = [200, 204]
    expected_body   = "OK"
    
    # Predictive health scoring
    latency_baseline_ms     = 50
    latency_degraded_factor = 2.5
    accelerated_probing     = true
    synthetic_when_idle     = true
  }

  # Circuit breaker
  circuit_breaker {
    enabled   = true
    threshold = 5    # Failures before tripping
    duration  = "30s"
  }

  # Route timeouts
  timeouts {
    enabled = true
    request = "30s"
  }
}
```

### 3. TCP Proxy Routes

Proxy raw TCP traffic (databases, custom protocols).

```hcl
proxy "postgres" {
  enabled  = true
  listen   = ":5432"
  sni      = "*.db.internal"        # Route based on SNI
  strategy = "least_conn"
  
  # Send PROXY protocol v2 header
  proxy_protocol = true
  
  # Global connection limit
  max_connections = 1000

  backend {
    address = "tcp://postgres-1:5432"
    weight  = 1
    
    # Per-backend connection limit
    max_connections = 500
  }

  backend {
    address = "tcp://postgres-2:5432"
    weight  = 1
  }

  # TCP health checks
  health_check {
    enabled  = true
    interval = "10s"
    timeout  = "2s"
    send     = "\\x00\\x00\\x00\\x2b\\x00\\x03\\x00\\x00\\x75\\x73\\x65\\x72\\x00"
    expect   = "\\x52"
  }
}
```

#### TCP Proxy Fields

| Field | Description | Example |
|-------|-------------|---------|
| `listen` | Listen address (required) | `":5432"` |
| `sni` | SNI pattern for routing | `"*.db.internal"` |
| `strategy` | Load balancing strategy | `"least_conn"` |
| `proxy_protocol` | Enable PROXY protocol | `true` |
| `max_connections` | Global connection limit | `1000` |
| `backend` | Backend server definitions | Multiple blocks |
| `health_check` | TCP health check configuration | Optional |

## Load Balancing Strategies

Agbero supports multiple load balancing strategies:

| Strategy | Description |
|----------|-------------|
| `round_robin` | Distributes requests sequentially (default) |
| `random` | Randomly selects a backend |
| `least_conn` | Picks backend with fewest active connections |
| `weighted_least_conn` | Least connections weighted by server capacity |
| `ip_hash` | Consistent hashing based on client IP |
| `url_hash` | Consistent hashing based on URL path |
| `least_response_time` | Picks backend with lowest latency |
| `power_of_two` | Randomly picks two, selects the better one |
| `consistent_hash` | Minimal disruption when backends change |
| `adaptive` | Dynamically learns optimal backend |
| `sticky` | Session affinity based on keys |

## Authentication Methods

### Basic Authentication

```hcl
route "/admin" {
  basic_auth {
    enabled = true
    realm   = "Admin Area"
    users   = [
      "admin:$2a$10$K2ul0gaUotcRRqTWnq4TRu06nxRo0yyO.ky8k..vpu2MgedAFLX4K",
      "editor:${env.EDITOR_HASH}"
    ]
  }
  backend { server { address = "http://localhost:3000" } }
}
```

### JWT Authentication

```hcl
route "/api/secure" {
  jwt_auth {
    enabled = true
    secret  = "${env.JWT_SECRET}"  # or "b64.encoded-secret"
    issuer  = "auth.example.com"
    audience = "myapi"
    
    # Map claims to headers for backend
    claim_map = {
      "sub"   = "X-User-ID"
      "email" = "X-User-Email"
      "role"  = "X-User-Role"
    }
  }
  backend { server { address = "http://api:8080" } }
}
```

### OAuth2 / OIDC

```hcl
route "/" {
  o_auth {
    enabled       = true
    provider      = "github"  # google, github, gitlab, oidc
    client_id     = "${env.GITHUB_CLIENT_ID}"
    client_secret = "${env.GITHUB_CLIENT_SECRET}"
    redirect_url  = "https://app.example.com/auth/callback"
    cookie_secret = "${env.OAUTH_COOKIE_SECRET}"
    email_domains = ["yourcompany.com"]
    scopes        = ["user:email"]
    
    # For OIDC/custom providers
    auth_url    = "https://auth.example.com/oauth2/auth"
    token_url   = "https://auth.example.com/oauth2/token"
    user_api_url = "https://auth.example.com/userinfo"
  }
  backend { server { address = "http://localhost:3000" } }
}
```

### Forward Authentication

Delegate auth to an external service:

```hcl
route "/secure" {
  forward_auth {
    enabled    = true
    name       = "auth-service"
    url        = "http://auth-service:9000/verify"
    timeout    = "2s"
    on_failure = "deny"  # or "allow"
    
    tls {
      enabled = true
      insecure_skip_verify = false
      client_cert = "${env.CLIENT_CERT}"
      client_key  = "${env.CLIENT_KEY}"
      ca          = "${env.CA_CERT}"
    }
    
    request {
      enabled        = true
      headers        = ["Authorization", "Cookie"]
      forward_method = true
      forward_uri    = true
      forward_ip     = true
      body_mode      = "limited"  # none, metadata, limited
      max_body       = 65536
      cache_key      = ["Authorization", "X-API-Key"]
    }
    
    response {
      enabled     = true
      copy_headers = ["X-User-Email", "X-User-Id"]
      cache_ttl    = "1m"
    }
  }
  backend { server { address = "http://localhost:3000" } }
}
```

## Headers & CORS

### Header Manipulation

```hcl
route "/api" {
  headers {
    enabled = true
    
    request {
      enabled = true
      set    = { 
        "X-API-Version" = "v2"
        "X-Request-ID"  = "${request_id}"
      }
      add    = { 
        "X-Trace-ID" = "trace-123"
      }
      remove = ["X-Powered-By", "Server"]
    }
    
    response {
      enabled = true
      set    = { 
        "Strict-Transport-Security" = "max-age=31536000"
        "X-Content-Type-Options"    = "nosniff"
      }
      add    = { 
        "X-Frame-Options" = "DENY"
      }
      remove = ["Server"]
    }
  }
  
  backend { server { address = "http://api:8080" } }
}
```

### CORS Configuration

```hcl
route "/api" {
  cors {
    enabled = true
    allowed_origins   = ["https://app.example.com", "https://admin.example.com"]
    allowed_methods   = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    allowed_headers   = ["Content-Type", "Authorization", "X-Requested-With"]
    exposed_headers   = ["X-Request-ID", "X-RateLimit-Remaining"]
    allow_credentials = true
    max_age           = 86400  # 24 hours
  }
  
  backend { server { address = "http://api:8080" } }
}
```

## Caching

### Memory Cache

```hcl
route "/static" {
  cache {
    enabled = true
    driver  = "memory"
    ttl     = "1h"
    methods = ["GET", "HEAD"]
    
    memory {
      max_items = 10000
    }
  }
  
  web {
    root = "/var/www/static"
  }
}
```

### Redis Cache (Distributed)

```hcl
route "/api" {
  cache {
    enabled = true
    driver  = "redis"
    ttl     = "5m"
    methods = ["GET"]
    
    redis {
      host       = "localhost"
      port       = 6379
      password   = "${env.REDIS_PASS}"
      db         = 0
      key_prefix = "agbero:cache:"
    }
  }
  
  backend { server { address = "http://api:8080" } }
}
```

## Rate Limiting

### Using Global Policies

```hcl
route "/api/public" {
  rate_limit {
    enabled    = true
    use_policy = "api-strict"  # Reference global policy
  }
  backend { server { address = "http://api:8080" } }
}
```

### Inline Rate Limit Rules

```hcl
route "/api/private" {
  rate_limit {
    enabled      = true
    ignore_global = true  # Skip global rate limits
    
    rule "custom" {
      enabled  = true
      name     = "custom-rule"
      prefixes = ["/api/v1/", "/api/v2/"]
      methods  = ["POST", "PUT", "DELETE"]
      requests = 50
      window   = "1m"
      burst    = 75
      key      = "header:X-API-Key"
    }
  }
  backend { server { address = "http://api:8080" } }
}
```

## Firewall Rules

### Route-Specific Firewall

```hcl
route "/admin" {
  firewall {
    enabled       = true
    ignore_global = true  # Skip global firewall
    
    # Apply named global rules
    apply_rules = ["block-scanners", "rate-limit-abuse"]
    
    # Or define inline rules
    rule "admin-only" {
      name        = "admin-only"
      description = "Block non-admin IPs"
      priority    = 10
      type        = "static"
      action      = "deny"
      duration    = "1h"
      
      match {
        any {
          location = "ip"
          pattern  = "!^10\\.0\\.0\\."
        }
      }
    }
  }
  backend { server { address = "http://admin:8080" } }
}
```

## WebAssembly (WASM) Plugins

```hcl
route "/filter" {
  wasm {
    enabled = true
    module  = "/etc/agbero/wasm/filter.wasm"
    
    # Grant explicit permissions
    access = ["headers", "config", "body", "method", "uri"]
    
    # Max body size to pass to WASM (0 = none)
    max_body_size = 1048576
    
    # Configuration passed to plugin
    config = {
      "block_countries" = "CN,RU"
      "debug_mode"      = "false"
      "api_key"         = "${env.API_KEY}"
    }
  }
  
  backend { server { address = "http://app:8080" } }
}
```

## Compression

```hcl
route "/" {
  compression {
    enabled = true
    type    = "brotli"  # gzip or brotli
    level   = 5         # 0-11 (0=no compression, 11=max)
  }
  
  web {
    root = "/var/www/html"
  }
}
```

## Fallback Responses

```hcl
route "/api" {
  fallback {
    enabled = true
    type    = "static"      # static, redirect, proxy
    status_code = 503
    body = "{\"error\":\"Service Temporarily Unavailable\"}"
    content_type = "application/json"
    
    # For redirect type
    # redirect_url = "https://backup.example.com"
    
    # For proxy type
    # proxy_url = "http://backup:8080"
    
    # Cache fallback response (seconds)
    cache_ttl = 30
  }
  
  backend {
    server { address = "http://api-1:8080" }
    server { address = "http://api-2:8080" }
  }
}
```

## TLS Configuration

```hcl
tls {
  mode = "letsencrypt"  # none, local, letsencrypt, custom_ca
  
  # For local certificates
  local {
    enabled  = true
    cert_file = "/etc/certs/server.crt"
    key_file  = "/etc/certs/server.key"
  }
  
  # For Let's Encrypt
  letsencrypt {
    enabled = true
    email   = "admin@example.com"
    staging = false
  }
  
  # For custom CA
  custom_ca {
    enabled = true
    root    = "/etc/ca/root.crt"
  }
  
  # Client authentication (mTLS)
  client_auth = "require_and_verify"  # none, request, require, require_and_verify, verify_if_given
  client_cas  = ["/etc/ca/client-ca.crt"]
}
```

## Limits

```hcl
limits {
  max_body_size = 10485760  # 10MB max request body
}
```

## Dynamic Values

Agbero supports dynamic value resolution:

```hcl
# Environment variables
secret = "${env.DATABASE_PASSWORD}"     # Shell expansion
secret = "env.DATABASE_PASSWORD"         # Direct env reference

# Base64-encoded values (for binary data)
private_key = "b64.LS0tLS1CRUdJTiBSU0EgUFJJVkFURS...="

# Combined
password = "b64.${env.B64_PASSWORD}"     # Both together
```

## Validation Rules

| Field | Rule |
|-------|------|
| `domains` | Must not contain protocol (http://) |
| `path` | Must start with `/` |
| `port` | Must be between 1-65535 |
| `allowed_ips` | Must be valid IP or CIDR |
| `cert_file` | Must be absolute path |
| `key_file` | Must be absolute path |

## Hot Reload

All host configuration changes are picked up automatically. No restart needed! Agbero watches `hosts.d` and reloads on any change:

```bash
# Just edit and save - Agbero does the rest
vim hosts.d/mysite.hcl

# Or force a reload
agbero config reload
```

## Next Steps

- [**Advanced Guide**](./advance.md) - Clustering, Git Deployments, WASM
- [**Global Configuration**](./global.md) - Main `agbero.hcl` settings
- [**CLI Reference**](./command.md) - Command-line documentation
