# Agbero Route Configuration Guide

This guide covers host and route configuration files in `hosts.d/*.hcl`. Each file defines one or more domains and their routing rules.

## 1. Basic Route Structure

Every route file defines domains and routes:

```hcl
# hosts.d/example.hcl
domains = ["example.com", "api.example.com"]

# Optional: Override global bind ports
bind = ["8080", "8443"]

# Optional: Custom 404 page
not_found_page = "/var/www/errors/404.html"

# Route definitions
route "/" {
  # ... route configuration
}
```
```hcl
# hosts.d/example.hcl
domains = ["example.com", "api.example.com"]

# Optional: Override global bind ports
bind = ["8080", "8443"]

# Optional: Custom 404 page
not_found_page = "/var/www/errors/404.html"

# Route definitions
route "/" {
  # ... route configuration
}
```

## 2. Serving Local Files & PHP

Serve static files or PHP applications from the local filesystem.

```hcl
# hosts.d/local.hcl
domains = ["localhost"]

route "/" {
  web {
    root    = "/var/www/html"  # Directory to serve
    listing = true              # Enable directory browsing
    index   = "index.html"      # Default index file
    
    # Enable PHP support (requires php-fpm)
    php {
      enabled = true
      address = "127.0.0.1:9000"
      index   = "index.php"
    }
  }
}
```

## 3. Reverse Proxy & Path Rewriting

Proxy requests to backend servers with path manipulation.

```hcl
# hosts.d/api.hcl
domains = ["api.example.com"]

route "/api" {
  # Remove '/api' prefix before forwarding
  strip_prefixes = ["/api"]
  
  # Rewrite old v1 endpoints
  rewrite {
    pattern = "^/v1/users/(.*)$"
    target  = "/users/$1?version=v1"
  }
  
  backend {
    strategy = "round_robin"  # round_robin, least_conn, ip_hash, etc.
    
    server {
      address = "http://backend-1:8080"
      weight  = 10
      
      # Streaming optimizations for WebSocket/SSE
      streaming {
        enabled        = true
        flush_interval = "100ms"
      }
    }
    
    server {
      address = "http://backend-2:8080"
      weight  = 5
    }
  }
  
  # Active health checks
  health_check {
    enabled   = true
    path      = "/health"
    interval  = "10s"
    timeout   = "5s"
    threshold = 3
    expected_status = [200, 204]
  }
  
  # Circuit breaker
  circuit_breaker {
    enabled   = true
    threshold = 10
    duration  = "30s"
  }
}
```

## 4. Authentication Methods

### Basic Authentication

```hcl
route "/admin" {
  basic_auth {
    enabled = true
    realm   = "Admin Area"
    users   = [
      "admin:$2a$10$...",  # bcrypt hash
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
    secret  = "${env.JWT_SECRET}"
    issuer  = "auth.example.com"
    
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
    email_domains = ["yourcompany.com"]  # Restrict by email domain
    scopes        = ["user:email"]
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
    url        = "http://auth-service:9000/verify"
    timeout    = "2s"
    on_failure = "deny"  # or "allow"
    
    request {
      headers        = ["Authorization", "Cookie"]
      forward_method = true
      forward_uri    = true
      forward_ip     = true
      body_mode      = "limited"  # none, metadata, limited
      max_body       = 65536
    }
    
    response {
      copy_headers = ["X-User-Email", "X-User-Id"]
      cache_ttl    = "1m"
    }
  }
  backend { server { address = "http://localhost:3000" } }
}
```

#### Example Forward Auth Server in Go

```go
package main

import (
	"net/http"
	"strings"
)

func main() {
	http.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		token := strings.TrimPrefix(auth, "Bearer ")

		if token == "super-secret-token" {
			w.Header().Set("X-User-Email", "admin@example.com")
			w.Header().Set("X-User-Id", "101")
			w.WriteHeader(http.StatusOK)
			return
		}

		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})

	http.ListenAndServe(":9000", nil)
}
```

## 5. Static Websites with GitOps (Cook)

Deploy static sites directly from Git repositories.

```hcl
# hosts.d/mysite.hcl
domains = ["mysite.example.com"]

tls {
  mode  = "letsencrypt"
  email = "admin@example.com"
}

route "/" {
  web {
    index = "index.html"
    spa   = true  # SPA mode - redirect 404 to index
    
    git {
      enabled  = true
      id       = "mysite_frontend"
      url      = "https://github.com/org/repo.git"
      branch   = "deploy-branch"
      sub_dir  = "dist"           # Serve from this subdirectory
      interval = "5m"              # Poll for changes
      secret   = "${env.WEBHOOK_SECRET}"  # For push-to-deploy
      
      auth {
        type = "ssh-key"
        ssh_key = "${b64.PRIVATE_KEY_BASE64}"
      }
    }
  }
}
```

### Webhook Endpoint

Trigger deployments instantly:

```bash
POST /.well-known/agbero/webhook/git/mysite_frontend
Headers:
  X-Hub-Signature-256: sha256=<hmac>
```

## 6. Route-Level Rate Limiting

Override or apply specific rate limits to routes.

```hcl
route "/api/public" {
  rate_limit {
    enabled      = true
    ignore_global = true  # Skip global rate limits
    use_policy   = "api-strict"  # Reference global policy
    
    # Or define inline rule
    rule "custom" {
      requests = 50
      window   = "1m"
      burst    = 75
      key      = "header:X-API-Key"
    }
  }
  backend { server { address = "http://api:8080" } }
}
```

## 7. Route-Level Firewall Rules

Apply firewall rules specific to a route.

```hcl
route "/admin" {
  firewall {
    enabled       = true
    ignore_global = true  # Skip global firewall
    
    # Apply named global rules
    apply_rules = ["block-scanners", "rate-limit-abuse"]
    
    # Or define inline rules
    rule "admin-only" {
      type   = "static"
      action = "deny"
      match {
        all {
          location = "ip"
          pattern  = "!^10\\.0\\.0\\."
        }
      }
    }
  }
  backend { server { address = "http://admin:8080" } }
}
```

## 8. TCP Proxy (Databases & Raw Sockets)

Route raw TCP traffic with SNI-based routing.

```hcl
# hosts.d/db.hcl
domains = ["db.internal"]

proxy "postgres" {
  enabled  = true
  listen   = ":5432"
  sni      = "*.db.internal"  # Route based on SNI
  strategy = "least_conn"
  
  # Send PROXY protocol v2 header
  proxy_protocol = true
  
  backend {
    address = "tcp://postgres-1:5432"
    weight  = 1
  }
  
  backend {
    address = "tcp://postgres-2:5432"
    weight  = 1
  }
  
  health_check {
    enabled  = true
    interval = "10s"
    timeout  = "2s"
    send     = "\\x00\\x00\\x00\\x2b\\x00\\x03\\x00\\x00\\x75\\x73\\x65\\x72\\x00"
    expect   = "\\x52"
  }
}
```

## 9. Headers & CORS

Modify request and response headers.

```hcl
route "/api" {
  headers {
    request {
      set    = { "X-API-Version" = "v2" }
      add    = { "X-Trace-ID" = "${request_id}" }
      remove = ["X-Powered-By"]
    }
    response {
      set    = { "Strict-Transport-Security" = "max-age=31536000" }
      add    = { "X-Frame-Options" = "DENY" }
      remove = ["Server"]
    }
  }
  
  cors {
    allowed_origins   = ["https://app.example.com"]
    allowed_methods   = ["GET", "POST", "PUT", "DELETE"]
    allowed_headers   = ["Content-Type", "Authorization"]
    exposed_headers   = ["X-Request-ID"]
    allow_credentials = true
    max_age           = 86400
  }
  
  backend { server { address = "http://api:8080" } }
}
```

## 10. WebAssembly (WASM) Plugins

Inject custom middleware compiled to WebAssembly.

```hcl
route "/filter" {
  wasm {
    enabled = true
    module  = "/etc/agbero/wasm/filter.wasm"
    
    # Grant explicit capabilities
    access = ["headers", "config"]
    
    # Configuration passed to plugin
    config = {
      "block_countries" = "CN,RU"
      "debug_mode"      = "false"
    }
  }
  
  backend { server { address = "http://app:8080" } }
}
```

## 11. Health Checks & Circuit Breakers

Configure advanced health checking and circuit breaking.

```hcl
route "/api" {
  backend {
    server { address = "http://app-1:8080" }
    server { address = "http://app-2:8080" }
  }
  
  health_check {
    enabled = true
    path    = "/health"
    interval = "10s"
    timeout  = "5s"
    
    # Advanced health scoring
    latency_baseline_ms     = 50      # 50ms baseline = 100% healthy
    latency_degraded_factor = 2.5     # >125ms reduces score
    accelerated_probing     = true    # Probe aggressively when unhealthy
    synthetic_when_idle     = true    # Probe even without traffic
  }
  
  circuit_breaker {
    enabled   = true
    threshold = 5   # Failures before tripping
    duration  = "30s"  # Time in open state
  }
}
```

## 12. Caching

Cache responses to reduce backend load.

```hcl
route "/static" {
  cache {
    enabled = true
    driver  = "memory"  # memory or redis
    ttl     = "1h"
    methods = ["GET", "HEAD"]
    
    memory {
      max_items = 10000
    }
    
    # redis {
    #   host = "localhost"
    #   port = 6379
    #   db   = 0
    #   key_prefix = "agbero:cache:"
    # }
  }
  
  web {
    root = "/var/www/static"
  }
}
```

## 13. Compression

Enable on-the-fly compression.

```hcl
route "/" {
  compression {
    enabled = true
    type    = "brotli"  # gzip or brotli
    level   = 5         # 0-11
  }
  
  web {
    root = "/var/www/html"
  }
}
```

## Next Steps

- [Advanced Guide](./advance.md) - Clustering, Git Deployments, and Firewall tuning
- [Plugin Guide](./plugin.md) - Write custom WebAssembly middleware
- [CLI Reference](./command.md) - Command-line interface documentation