# =============================================================================
# FULL HOST CONFIGURATION REFERENCE
# =============================================================================

# -------------------------------------------------------------
# 1. HOST META
# -------------------------------------------------------------
# Domains to match (supports wildcards)
domains = ["example.com", "*.api.example.com"]

# Optional: Bind specific ports (overrides global)
bind = ["8080", "8443"]

# Optional: Custom 404 page for this host
# not_found_page = "/path/to/404.html"

# -------------------------------------------------------------
# 2. TLS SETTINGS
# -------------------------------------------------------------
tls {
  # mode: auto, local, letsencrypt, custom_ca, none
  mode = "auto"

  # For mode = "local"
  local {
    enabled   = "on"
    cert_file = "/etc/certs/example.pem"
    key_file  = "/etc/certs/example.key"
  }

  # For mode = "letsencrypt"
  lets_encrypt {
    enabled     = "on"
    email       = "admin@example.com"
    staging     = false
    short_lived = false
  }

  # mTLS: Client Certificate Authentication
  client_auth = "require_and_verify" # none, request, require, verify_if_given, require_and_verify
  client_cas  = ["/etc/certs/ca.pem"]
}

# -------------------------------------------------------------
# 3. GLOBAL HOST MIDDLEWARE
# -------------------------------------------------------------
limits {
  max_body_size = 52428800 # 50MB
}

headers {
  enabled = "on"
  request {
    enabled = "on"
    set     = { "X-Host-ID" = "primary" }
    add     = { "X-Trace" = "${request_id}" }
    remove  = ["X-Powered-By"]
  }
  response {
    enabled = "on"
    set     = { "Strict-Transport-Security" = "max-age=31536000" }
  }
}

error_pages {
  pages   = { "503" = "/errors/503.html" }
  default = "/errors/generic.html"
}

# =============================================================================
# 4. HTTP ROUTES
# =============================================================================

# --- A. Reverse Proxy Route ---
route {
  enabled = "on"
  path    = "/api"

  # Strip prefix before sending to backend
  strip_prefixes = ["/api"]

  # Access Control
  allowed_ips = ["10.0.0.0/8"]

  # Backend Pool
  backend {
    enabled  = "on"
    strategy = "weighted_least_conn" # round_robin, ip_hash, least_conn, etc.

    server {
      address = "http://backend-1:8080"
      weight  = 10

      # Health criteria for this specific backend
      criteria {
        source_ips = ["10.0.0.0/8"]
      }

      # WebSocket/Streaming optimizations
      streaming {
        enabled        = "on"
        flush_interval = "100ms"
      }
    }

    server {
      address = "http://backend-2:8080"
      weight  = 5
    }
  }

  # Active Health Checks
  health_check {
    enabled   = "on"
    path      = "/health"
    interval  = "10s"
    timeout   = "5s"
    threshold = 3
    expected_status = [200, 204]
  }

  # Circuit Breaker
  circuit_breaker {
    enabled   = "on"
    threshold = 10
    duration  = "30s"
  }

  # Authentication: JWT
  jwt_auth {
    enabled = "on"
    secret  = "env.JWT_SECRET"
    claims_to_headers = { "sub" = "X-User" }
  }

  # Rate Limiting
  rate_limit {
    enabled = "on"
    rule {
      enabled  = "on"
      requests = 100
      window   = "1m"
      key      = "header:Authorization"
    }
  }

  # WebAssembly Plugin
  wasm {
    enabled = "on"
    module  = "/etc/agbero/plugins/auth.wasm"
    access  = ["headers", "body"]
  }
}

# --- B. Static Web Route ---
route {
  enabled = "on"
  path    = "/"

  web {
    enabled = "on"
    root    = "/var/www/html"
    index   = ["index.html"]
    listing = true # Enable directory listing
    spa     = false # SPA mode (redirect 404 to index)

    # PHP Integration
    php {
      enabled = "on"
      address = "unix:/run/php/php-fpm.sock"
    }
  }

  # Authentication: Basic
  basic_auth {
    enabled = "on"
    users   = ["admin:$2a$10$..."] # bcrypt hash
    realm   = "Admin Area"
  }

  # Compression
  compression_config {
    enabled = "on"
    type    = "brotli"
    level   = 4
  }

  # Caching
  cache {
    enabled = "on"
    driver  = "memory"
    ttl     = "1h"
  }
}

# =============================================================================
# 5. TCP PROXY (Layer 4)
# =============================================================================
proxy {
  enabled = "on"
  name    = "database"
  listen  = ":5432"

  # Routing based on TLS SNI
  sni     = "db.internal"

  strategy       = "least_conn"
  proxy_protocol = true # Send PROXY v2 header

  backend {
    address = "tcp://10.0.0.50:5432"
    weight  = 1
  }

  health_check {
    enabled  = "on"
    interval = "5s"
    # Plain TCP connect check
  }
}