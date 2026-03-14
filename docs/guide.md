# Agbero Guide: Practical Examples & Use Cases

## Understanding Configuration

Agbero uses HCL (HashiCorp Configuration Language) with a hierarchical structure:

```
agbero.hcl (global)
└── hosts.d/*.hcl (host definitions)
└── route {} / proxy {} (routes)
```

### Global Configuration (`agbero.hcl`)

```hcl
version = 1

bind {
  http  = [":80"]          # HTTP listeners
  https = [":443"]         # HTTPS listeners
  redirect = true          # Auto HTTP→HTTPS
}

storage {
  hosts_dir = "./hosts.d"  # Where host configs live
  certs_dir = "./certs.d"  # TLS certificates
  data_dir  = "./data.d"   # Runtime data
  logs_dir  = "./logs.d"   # Log files
  work_dir  = "./work.d"    # Git deployment workspace
}

timeouts {
  enabled    = true
  read       = "30s"       # Global read timeout
  write      = "30s"       # Global write timeout
  idle       = "120s"      # Keep-alive timeout
  read_header = "5s"       # Header read timeout
}
```

### Host Configuration (`hosts.d/example.hcl`)

```hcl
domains = ["app.example.com", "api.example.com"]

# TLS configuration
tls {
  mode = "letsencrypt"  # or "local", "local_auto", "custom_ca"
  email = "admin@example.com"  # for Let's Encrypt
}

# Routes
route "/" {
  web {
    root = "/var/www/html"
    index = "index.html"
  }
}

route "/api" {
  backend {
    strategy = "round_robin"
    server { address = "http://localhost:3000" }
    server { address = "http://localhost:3001" }
  }
  
  health_check {
    path = "/health"
    interval = "10s"
  }
}
```

## Common Use Cases

### 1. Static Website with HTTPS

```hcl
# hosts.d/mysite.hcl
domains = ["mysite.example.com"]

tls {
  mode = "letsencrypt"
  email = "me@example.com"
}

route "/" {
  web {
    root = "/var/www/mysite"
    index = "index.html"
    spa = true  # For React/Vue apps
  }
}

# Optional: Compress assets
compression = true
```

### 2. Reverse Proxy with Load Balancing

```hcl
# hosts.d/api.hcl
domains = ["api.example.com"]

route "/v1" {
  backend {
    strategy = "least_conn"  # Best for long-lived connections
    
    server {
      address = "http://10.0.0.10:8080"
      weight = 2  # Twice the capacity
    }
    
    server {
      address = "http://10.0.0.11:8080"
      weight = 1
    }
    
    server {
      address = "http://10.0.0.12:8080"
      weight = 1
      criteria {  # Only for internal IPs
        source_ips = ["10.0.0.0/8"]
      }
    }
  }
  
  # Health checks
  health_check {
    path = "/health"
    interval = "5s"
    timeout = "2s"
    expected_status = [200, 204]
  }
  
  # Circuit breaker
  circuit_breaker {
    threshold = 5   # Trip after 5 failures
    duration = "30s"  # Try recovery after 30s
  }
}
```

### 3. WebSocket Support

```hcl
# hosts.d/ws.hcl
domains = ["ws.example.com"]

route "/" {
  backend {
    server {
      address = "http://localhost:8080"
      streaming {  # Enable WebSocket support
        enabled = true
        flush_interval = "100ms"
      }
    }
  }
  
  # No timeout for WebSockets
  timeouts {
    enabled = false
  }
}
```

### 4. JWT Authentication Gateway

```hcl
# hosts.d/secure.hcl
domains = ["secure.example.com"]

route "/api" {
  # Validate JWT before forwarding
  jwt_auth {
    secret = "${env.JWT_SECRET}"  # HMAC secret
    issuer = "auth.example.com"
    
    # Map claims to headers
    claim_map = {
      "sub" = "X-User-ID"
      "email" = "X-User-Email"
      "role" = "X-User-Role"
    }
  }
  
  backend {
    server { address = "http://api:8080" }
  }
}
```

### 5. Rate Limiting

```hcl
# hosts.d/rate-limited.hcl
domains = ["api.example.com"]

route "/public" {
  rate_limit {
    # Global policy reference
    use_policy = "public-api"
    
    # Or inline definition
    rule {
      requests = 100
      window = "1m"
      burst = 20
      key = "ip"  # Rate limit by IP
    }
  }
  
  backend {
    server { address = "http://api:8080" }
  }
}

# Global rate limit policies (in agbero.hcl)
rate_limits {
  policy "public-api" {
    requests = 1000
    window = "1h"
    burst = 100
    key = "header:X-API-Key"
  }
}
```

### 6. Basic Authentication

```hcl
# hosts.d/admin.hcl
domains = ["admin.example.com"]

route "/" {
  basic_auth {
    enabled = true
    realm = "Admin Area"
    users = [
      "admin:$2a$10$N9qo8uLOickgx2ZMRZoMye...",  # bcrypt hash
      "viewer:${env.VIEWER_PASSWORD}"  # from env var
    ]
  }
  
  backend {
    server { address = "http://admin-dashboard:8080" }
  }
}
```

### 7. Forward Authentication

```hcl
# hosts.d/auth-proxy.hcl
domains = ["app.example.com"]

route "/" {
  forward_auth {
    url = "http://auth-service:9000/verify"
    timeout = "5s"
    on_failure = "deny"  # or "allow" for fail-open
    
    request {
      headers = ["Authorization", "Cookie"]
      forward_method = true
      forward_uri = true
      forward_ip = true
    }
    
    response {
      copy_headers = ["X-User-Email", "X-User-Roles"]
      cache_ttl = "5m"  # Cache successful auth
    }
  }
  
  backend {
    server { address = "http://app:8080" }
  }
}
```

### 8. TCP Proxy (Database/Redis)

```hcl
# hosts.d/db.hcl (note: at host level, not route)
domains = ["db.internal"]  # For SNI routing

proxy "postgres" {
  enabled = true
  listen = ":5432"
  sni = "*.db.internal"  # Route by SNI
  strategy = "least_conn"
  
  # Enable PROXY protocol for real IPs
  proxy_protocol = true
  
  backend {
    address = "postgres-1:5432"
    weight = 2
  }
  
  backend {
    address = "postgres-2:5432"
    weight = 1
  }
  
  health_check {
    enabled = true
    interval = "5s"
    # PostgreSQL startup message
    send = "Q\0\0\0\x1f\0\0\0\x03\0\0user\0user\0\0"
    expect = "R"  # Authentication request
  }
}
```

### 9. PHP Application

```hcl
# hosts.d/php.hcl
domains = ["php.example.com"]

route "/" {
  web {
    root = "/var/www/php-app"
    index = "index.php"
    
    php {
      enabled = true
      address = "unix:/var/run/php/php8.2-fpm.sock"
      # or: address = "127.0.0.1:9000"
    }
  }
}
```

### 10. A/B Testing with Traffic Splitting

```hcl
# hosts.d/abtest.hcl
domains = ["app.example.com"]

route "/" {
  backend {
    strategy = "round_robin"
    
    # Version A - 80% of traffic
    server {
      address = "http://app-v1:8080"
      weight = 8
    }
    
    # Version B - 20% of traffic
    server {
      address = "http://app-v2:8080"
      weight = 2
    }
    
    # Internal users always get version B
    server {
      address = "http://app-v2:8080"
      criteria {
        headers = {
          "X-Internal" = "true"
        }
      }
    }
  }
}
```

## Monitoring & Debugging

### Health Checks

```bash
# Check system health
curl http://localhost:9090/uptime | jq

# Prometheus metrics
curl http://localhost:9090/metrics

# Live log tail
agbero logs -f
```

### Hot Reload

```bash
# Reload configuration without restart
agbero reload

# Or send SIGHUP manually
kill -SIGHUP $(pgrep agbero)
```

### Debug Mode

```bash
# Run with debug logging
agbero run --dev

# Or in config:
logging {
  level = "debug"
}
```

## Next Steps

- [Advanced Guide](./advanced.md) for clustering, Git deployments, WASM, and custom health scoring
- [API Reference](./api.md) for complete configuration options


