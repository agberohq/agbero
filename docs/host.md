# Agbero Host Configuration (hosts.d/*.hcl)

This guide covers host and route configuration files in `hosts.d/*.hcl`. Each file defines one or more domains and their routing rules.

## 1. Basic Host Structure

Every host file defines domains and routes:

```hcl
# hosts.d/example.hcl
domains = ["example.com", "api.example.com", "*.apps.example.com"]

# Optional: Override global bind ports for this host
bind = ["8080", "8443"]

# Optional: Custom 404 page for this host
not_found_page = "/var/www/errors/404.html"

# Optional: Enable compression for all routes on this host
compression = true

# TLS configuration (per host)
tls {
  mode = "auto"  # auto, local, letsencrypt, custom_ca, none
  # ... TLS settings
}

# Route definitions
route "/" {
  # ... route configuration
}

route "/api" {
  # ... another route
}
```

---

## 2. Route Structure

Each route has a path label and various configuration blocks:

```hcl
route "/path" {
  enabled = true  # Enable/disable this route
  
  # Path manipulation
  strip_prefixes = ["/path", "/api"]
  
  # IP restrictions
  allowed_ips = ["10.0.0.0/8", "192.168.1.0/24"]
  
  # URL rewrites
  rewrite {
    pattern = "^/old/(.*)$"
    target  = "/new/$1"
  }
  
  # Route type: EITHER web (static) OR backend (proxy)
  web { ... }        # Static file serving
  # OR
  backend { ... }    # Reverse proxy
}
```

---

## 3. Web Routes (Static File Serving)

Serve static files, directories, and PHP applications.

### Basic Static Site

```hcl
route "/" {
  web {
    root    = "/var/www/html"  # Directory to serve
    listing = true              # Enable directory browsing
    index   = ["index.html"]      # Default index file
    spa     = false             # SPA mode (redirect 404 to index)
  }
}
```

### With Markdown Rendering

```hcl
route "/docs" {
  web {
    root = "/var/www/docs"
    
    markdown {
      enabled = true
      view    = "browse"        # "normal" or "browse"
      
      highlight {
        enabled = true
        theme   = "dracula"     # github, dracula, monokai, nord, etc.
      }
      
      unsafe_html = false        # Allow raw HTML in markdown
      toc = true                 # Generate table of contents
    }
  }
}
```

### With PHP Support

```hcl
route "/app" {
  web {
    root = "/var/www/app"
    
    php {
      enabled = true
      address = "127.0.0.1:9000"  # or "unix:/run/php/php-fpm.sock"
      index   = ["index.php"]
    }
  }
}
```

### With Git Integration (Cook)

```hcl
route "/" {
  web {
    index = ["index.html"]
    
    git {
      enabled  = true
      id       = "frontend_app"
      url      = "https://github.com/org/repo.git"
      branch   = "main"
      sub_dir  = "dist"           # Serve from this subdirectory
      interval = "5m"              # Polling interval
      secret   = "${env.WEBHOOK_SECRET}"  # For webhook verification
      
      auth {
        type = "ssh-key"           # "basic", "ssh-key", "ssh-agent"
        username = "git"
        ssh_key = "${b64.PRIVATE_KEY_BASE64}"
      }
    }
  }
}
```

**Webhook Endpoint:**
```
POST /.well-known/agbero/webhook/git/frontend_app
Headers:
  X-Hub-Signature-256: sha256=<hmac>
```

---

## 4. Proxy Routes (Reverse Proxy)

Proxy requests to backend servers.

### Basic Proxy

```hcl
route "/api" {
  backend {
    # Load balancing strategy
    strategy = "round_robin"  # round_robin, least_conn, ip_hash, 
                              # url_hash, random, weighted_least_conn,
                              # least_response_time, power_of_two,
                              # consistent_hash, adaptive, sticky
    
    # Backend servers
    server {
      address = "http://backend-1:8080"
      weight  = 10
    }
    
    server {
      address = "http://backend-2:8080"
      weight  = 5
    }
  }
}
```

### With Path Stripping

```hcl
route "/api/v2" {
  strip_prefixes = ["/api/v2"]  # Remove prefix before forwarding
  
  backend {
    server {
      address = "http://api-service:8080"
    }
  }
}
```

### With Streaming Optimizations

```hcl
route "/stream" {
  backend {
    server {
      address = "http://streaming-service:8080"
      
      streaming {
        enabled        = true
        flush_interval = "100ms"  # For SSE/WebSocket
      }
    }
  }
}
```

### With Backend Selection Criteria

```hcl
route "/api" {
  backend {
    server {
      address = "http://us-east:8080"
      criteria {
        source_ips = ["10.0.0.0/8"]  # Only route internal traffic here
      }
    }
    
    server {
      address = "http://global:8080"
      # No criteria - default for everyone else
    }
  }
}
```

---

## 5. Health Checks

Configure active health checking for backends.

```hcl
route "/api" {
  backend {
    server { address = "http://app-1:8080" }
    server { address = "http://app-2:8080" }
  }
  
  health_check {
    enabled = true
    path    = "/health"           # HTTP endpoint
    method  = "GET"                # HTTP method
    
    interval = "10s"               # Check frequency
    timeout  = "5s"                 # Request timeout
    threshold = 3                   # Failures before marking unhealthy
    
    # Expected response
    expected_status = [200, 204]    # Acceptable status codes
    expected_body   = "OK"           # Expected body content
    
    # Advanced health scoring
    latency_baseline_ms     = 50     # 50ms baseline = 100% healthy
    latency_degraded_factor = 2.5    # >125ms reduces score
    
    # Probe behavior
    accelerated_probing = true       # Probe aggressively when unhealthy
    synthetic_when_idle = true       # Probe even without traffic
  }
}
```

---

## 6. Circuit Breaker

Protect backends from cascading failures.

```hcl
route "/api" {
  backend {
    server { address = "http://app-1:8080" }
    server { address = "http://app-2:8080" }
  }
  
  circuit_breaker {
    enabled   = true
    threshold = 5    # Failures before tripping
    duration  = "30s"  # Time in open state before half-open
  }
}
```

---

## 7. Authentication Methods

### Basic Authentication

```hcl
route "/admin" {
  basic_auth {
    enabled = true
    realm   = "Admin Area"
    users   = [
      "admin:$2a$10$K2ul0gaUotcRRqTWnq4TRu06nxRo0yyO.ky8k..vpu2MgedAFLX4K",  # bcrypt hash
      "editor:${env.EDITOR_HASH}"
    ]
  }
  
  web { root = "/var/www/admin" }
}
```

### JWT Authentication

```hcl
route "/api/secure" {
  jwt_auth {
    enabled = true
    secret  = "${env.JWT_SECRET}"
    issuer  = "auth.example.com"     # Optional: validate issuer
    
    # Map claims to headers for backend
    claim_map = {
      "sub"   = "X-User-ID"
      "email" = "X-User-Email"
      "role"  = "X-User-Role"
    }
  }
  
  backend {
    server { address = "http://api:8080" }
  }
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
    
    cookie_secret = "${env.OAUTH_COOKIE_SECRET}"  # 16+ chars
    email_domains = ["yourcompany.com"]  # Restrict by email domain
    scopes        = ["user:email"]
    
    # For OIDC provider
    # auth_url   = "https://accounts.google.com"
    # token_url  = "https://oauth2.googleapis.com/token"
    # user_api_url = "https://openidconnect.googleapis.com/v1/userinfo"
  }
  
  web { root = "/var/www/app" }
}
```

### Forward Authentication

Delegate auth to an external service:

```hcl
route "/secure" {
  forward_auth {
    enabled    = true
    name       = "auth-service"  # Optional identifier
    url        = "http://auth:9000/verify"
    timeout    = "2s"
    on_failure = "deny"  # "allow" or "deny"
    
    # mTLS configuration (optional)
    tls {
      enabled = false
      insecure_skip_verify = false
      client_cert = "${env.CLIENT_CERT}"
      client_key  = "${env.CLIENT_KEY}"
      ca = "${env.CA_CERT}"
    }
    
    request {
      enabled = true
      headers = ["Authorization", "Cookie", "X-Original-URI"]
      forward_method = true
      forward_uri    = true
      forward_ip     = true
      body_mode      = "limited"  # "none", "metadata", "limited"
      max_body       = 65536
      cache_key      = ["Authorization", "X-Original-URI"]
    }
    
    response {
      enabled = true
      copy_headers = ["X-User-Email", "X-User-Id", "X-Roles"]
      cache_ttl    = "1m"  # Cache successful auth decisions
    }
  }
  
  backend {
    server { address = "http://app:8080" }
  }
}
```

---

## 8. Rate Limiting

Apply rate limits to specific routes.

```hcl
route "/api/public" {
  rate_limit {
    enabled       = true
    ignore_global = true   # Skip global rate limits
    
    # Reference a named policy from global config
    use_policy = "api-strict"
    
    # Or define inline rule
    rule {
      enabled  = true
      name     = "custom-limit"
      prefixes = ["/api/public"]
      methods  = ["GET", "POST"]
      requests = 50
      window   = "1m"
      burst    = 75
      key      = "header:X-API-Key"  # ip, header:X, cookie:X, query:X
    }
  }
  
  backend { server { address = "http://api:8080" } }
}
```

---

## 9. Firewall Rules

Apply Web Application Firewall rules to specific routes.

```hcl
route "/admin" {
  firewall {
    enabled       = true
    ignore_global = true   # Skip global firewall
    
    # Apply named global rules
    apply_rules = ["block-scanners", "rate-limit-abuse"]
    
    # Or define inline rules
    rule {
      name        = "admin-only"
      type        = "static"
      action      = "deny"
      priority    = 10
      
      match {
        all {
          location = "ip"
          pattern  = "!^10\\.0\\.0\\."
        }
      }
    }
    
    rule {
      name   = "rate-limit-admin"
      type   = "dynamic"
      action = "rate-limit"
      
      match {
        threshold {
          enabled = true
          count   = 30
          window  = "1m"
          track_by = "ip"
        }
      }
    }
  }
  
  backend { server { address = "http://admin:8080" } }
}
```

---

## 10. Headers Manipulation

Modify request and response headers.

```hcl
route "/api" {
  headers {
    enabled = true
    
    request {
      enabled = true
      set = {
        "X-API-Version" = "v2"
        "X-Request-ID"  = "${request_id}"
      }
      add = {
        "X-Trace-ID"    = "${trace_id}"
      }
      remove = ["X-Powered-By", "X-AspNet-Version"]
    }
    
    response {
      enabled = true
      set = {
        "Strict-Transport-Security" = "max-age=31536000"
        "X-Content-Type-Options"    = "nosniff"
        "X-Frame-Options"           = "DENY"
      }
      add = {
        "X-Cache-Status" = "${cache_status}"
      }
      remove = ["Server"]
    }
  }
  
  backend { server { address = "http://api:8080" } }
}
```

---

## 11. CORS Configuration

Configure Cross-Origin Resource Sharing.

```hcl
route "/api" {
  cors {
    enabled = true
    allowed_origins = [
      "https://app.example.com",
      "https://admin.example.com"
    ]
    allowed_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    allowed_headers = [
      "Content-Type",
      "Authorization",
      "X-Requested-With"
    ]
    exposed_headers = [
      "X-Request-ID",
      "X-RateLimit-Limit"
    ]
    allow_credentials = true
    max_age = 86400  # seconds
  }
  
  backend { server { address = "http://api:8080" } }
}
```

---

## 12. Caching

Cache responses to reduce backend load.

```hcl
route "/static" {
  cache {
    enabled = true
    driver  = "memory"  # "memory" or "redis"
    ttl     = "1h"
    methods = ["GET", "HEAD"]
    
    memory {
      max_items = 10000
    }
    
    # redis {
    #   host = "localhost"
    #   port = 6379
    #   password = "${env.REDIS_PASS}"
    #   db = 0
    #   key_prefix = "agbero:cache:"
    # }
  }
  
  web { root = "/var/www/static" }
}
```

---

## 13. Compression

Enable on-the-fly compression.

```hcl
route "/" {
  compression {
    enabled = true
    type    = "brotli"  # "gzip" or "brotli"
    level   = 5         # 0-11
  }
  
  web { root = "/var/www/html" }
}
```

---

## 14. Timeouts

Per-route request timeouts.

```hcl
route "/slow-api" {
  timeouts {
    enabled = true
    request = "60s"  # Override global timeout for this route
  }
  
  backend { server { address = "http://slow-backend:8080" } }
}
```

---

## 15. Fallback Responses

Route-specific fallback when backends are unavailable.

```hcl
route "/api" {
  fallback {
    enabled = true
    type    = "static"      # "static", "redirect", "proxy"
    status_code = 503
    body = "{\"error\":\"Service temporarily unavailable\"}"
    content_type = "application/json"
    # redirect_url = "https://backup.example.com"  # For type=redirect
    # proxy_url = "http://backup:8080"              # For type=proxy
    cache_ttl = 30  # seconds
  }
  
  backend {
    server { address = "http://primary:8080" }
  }
}
```

---

## 16. Error Pages

Route-specific error pages.

```hcl
route "/" {
  error_pages {
    pages = {
      "404" = "/var/www/errors/404.html"
      "500" = "/var/www/errors/500.html"
      "503" = "/var/www/errors/maintenance.html"
    }
    default = "/var/www/errors/error.html"
  }
  
  web { root = "/var/www/site" }
}
```

---

## 17. WebAssembly (WASM) Plugins

Inject custom middleware compiled to WebAssembly.

```hcl
route "/filter" {
  wasm {
    enabled = true
    module  = "/etc/agbero/wasm/filter.wasm"
    max_body_size = 1048576  # 1MB
    
    # Grant explicit capabilities
    access = ["headers", "body", "method", "uri", "config"]
    
    # Configuration passed to plugin
    config = {
      "block_countries" = "CN,RU"
      "debug_mode"      = "false"
      "api_keys"        = "key1,key2,key3"
    }
  }
  
  backend { server { address = "http://app:8080" } }
}
```

---

## 18. TLS Configuration per Host

Override TLS settings for specific hosts.

```hcl
domains = ["secure.example.com"]

tls {
  mode = "letsencrypt"  # "auto", "local", "letsencrypt", "custom_ca", "none"
  email = "admin@example.com"  # For Let's Encrypt
  
  # For mode = "local"
  local {
    enabled   = true
    cert_file = "/etc/certs/example.pem"
    key_file  = "/etc/certs/example.key"
  }
  
  # For mode = "custom_ca"
  custom_ca {
    enabled = true
    root    = "/etc/certs/ca.pem"
  }
  
  # mTLS: Client Certificate Authentication
  client_auth = "require_and_verify"  # "none", "request", "require", 
                                      # "verify_if_given", "require_and_verify"
  client_cas = ["/etc/certs/client-ca.pem"]
}

route "/" {
  web { root = "/var/www/secure" }
}
```

---

## 19. TCP Proxy Routes

Route raw TCP traffic (Layer 4).

```hcl
# TCP proxies are defined at the host level, not under route
proxy "postgres" {
  enabled = true
  listen  = ":5432"
  
  # Route based on TLS SNI (optional)
  sni     = "*.db.internal"
  
  # Load balancing strategy
  strategy = "least_conn"  # round_robin, least_conn, random
  
  # Send PROXY protocol v2 header
  proxy_protocol = true
  
  # Maximum concurrent connections
  max_connections = 1000
  
  # Backend servers
  backend {
    address = "tcp://postgres-1:5432"
    weight  = 10
  }
  
  backend {
    address = "tcp://postgres-2:5432"
    weight  = 10
  }
  
  # TCP health check
  health_check {
    enabled  = true
    interval = "10s"
    timeout  = "2s"
    send     = "\x00\x00\x00\x2b\x00\x03\x00\x00\x75\x73\x65\x72\x00"  # PostgreSQL startup
    expect   = "\x52"  # 'R' for authentication request
  }
}

proxy "redis" {
  enabled = true
  listen  = ":6379"
  strategy = "round_robin"
  
  backend { address = "tcp://redis-1:6379" }
  backend { address = "tcp://redis-2:6379" }
  
  health_check {
    enabled  = true
    interval = "5s"
    timeout  = "1s"
    send     = "PING\r\n"
    expect   = "+PONG"
  }
}
```

---

## 20. Complete Example

A comprehensive host configuration with multiple route types:

```hcl
# hosts.d/example.com.hcl
domains = [
  "example.com",
  "api.example.com",
  "static.example.com"
]

bind = ["8080", "8443"]

# Host-level TLS
tls {
  mode = "letsencrypt"
  email = "admin@example.com"
}

# Host-level headers
headers {
  enabled = true
  response {
    set = {
      "Strict-Transport-Security" = "max-age=31536000"
    }
  }
}

# Main website - static files
route "/" {
  web {
    root = "/var/www/site"
    index = ["index.html"]
    
    git {
      enabled = true
      id = "main-site"
      url = "https://github.com/org/site.git"
      branch = "main"
      interval = "5m"
    }
    
    markdown {
      enabled = true
      view = "browse"
      highlight { theme = "github" }
    }
  }
}

# API - reverse proxy with auth and rate limiting
route "/api" {
  strip_prefixes = ["/api"]
  
  jwt_auth {
    enabled = true
    secret = "${env.JWT_SECRET}"
    claim_map = { "sub" = "X-User-ID" }
  }
  
  rate_limit {
    enabled = true
    rule {
      requests = 1000
      window = "1m"
      key = "header:X-User-ID"
    }
  }
  
  cors {
    enabled = true
    allowed_origins = ["https://app.example.com"]
    allow_credentials = true
  }
  
  backend {
    strategy = "least_response_time"
    
    server {
      address = "http://api-v1:8080"
      weight = 10
    }
    
    server {
      address = "http://api-v2:8080"
      weight = 5
    }
  }
  
  health_check {
    enabled = true
    path = "/health"
    interval = "10s"
  }
  
  circuit_breaker {
    enabled = true
    threshold = 5
    duration = "30s"
  }
}

# Admin area - protected with firewall
route "/admin" {
  firewall {
    enabled = true
    rule {
      name = "admin-ip-restrict"
      type = "static"
      action = "deny"
      match {
        all {
          location = "ip"
          pattern = "!^10\\.0\\.0\\."
        }
      }
    }
  }
  
  basic_auth {
    enabled = true
    users = ["admin:${env.ADMIN_HASH}"]
  }
  
  backend {
    server { address = "http://admin-service:8080" }
  }
}

# PostgreSQL TCP proxy
proxy "postgres" {
  enabled = true
  listen = ":5432"
  strategy = "least_conn"
  
  backend { address = "tcp://postgres-1:5432" }
  backend { address = "tcp://postgres-2:5432" }
  
  health_check {
    enabled = true
    interval = "10s"
  }
}
```

---

## Webhook Endpoints

For Git-integrated routes, Agbero exposes webhook endpoints:

```
# Trigger deployment for a specific git ID
POST /.well-known/agbero/webhook/git/frontend_app

# Headers for GitHub/GitLab
X-Hub-Signature-256: sha256=<hmac>
X-GitHub-Event: push
X-GitLab-Event: Push Hook
```

---

## Environment Variables in Configuration

```hcl
secret = "${env.JWT_SECRET}"
path   = "${env.CONFIG_DIR}/certs"
users  = ["admin:${env.ADMIN_HASH}"]
```

Base64-encoded values:
```hcl
ssh_key = "b64.${env.PRIVATE_KEY_BASE64}"
```

---

## Next Steps

- [Advanced Guide](./advance.md) - Clustering, Git Deployments, and Firewall tuning
- [Plugin Guide](./plugin.md) - Write custom WebAssembly middleware
- [CLI Reference](./command.md) - Command-line interface documentation