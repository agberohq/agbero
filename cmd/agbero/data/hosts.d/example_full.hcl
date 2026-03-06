# =============================================================================
# EXAMPLE HOST CONFIGURATION
# File: hosts.d/example.hcl
# Purpose: Demonstrates full range of host/route options for agbero
# =============================================================================

# Domains this host responds to (supports wildcards)
domains = [
  "example.localhost",
  "www.example.localhost",
  # "example.com",           # Production domain
  # "*.api.example.com",     # Wildcard subdomain
]

# Optional: Override global bind ports for this host only
# bind = ["8080", "8443"]

# Custom 404 page for this host (optional)
# not_found_page = "/etc/agbero/hosts/example/404.html"

# Enable response compression (gzip/brotli) for this host
compression = true

# -------------------------------------------------------------
# TLS SETTINGS (per-host override)
# -------------------------------------------------------------
tls {
  # Mode: auto, none, local, letsencrypt, custom_ca
  # auto: uses letsencrypt for public domains, local for localhost
  mode = "auto"

  # For mode = "local": manually managed certificates
  # local {
  #   enabled  = on
  #   cert_file = "/etc/ssl/certs/example.localhost.crt"
  #   key_file  = "/etc/ssl/private/example.localhost.key"
  # }

  # For mode = "letsencrypt": override global settings
  # letsencrypt {
  #   enabled = on
  #   email   = "admin@example.com"
  #   staging = false
  # }

  # For mode = "custom_ca": use internal CA
  # custom_ca {
  #   enabled = on
  #   root    = "/etc/ssl/ca/root-ca.crt"
  # }

  # Client certificate authentication (mTLS)
  # client_auth = "require_and_verify"  # none, request, require, verify_if_given, require_and_verify
  # client_cas = ["/etc/ssl/ca/client-ca.crt"]
}

# -------------------------------------------------------------
# REQUEST LIMITS (per-host)
# -------------------------------------------------------------
limits {
  # Maximum request body size in bytes (default: 2MB)
  max_body_size = 52428800  # 50MB for file uploads
}

# -------------------------------------------------------------
# HEADER MANIPULATION (per-host)
# -------------------------------------------------------------
headers {
  enabled = on

  # Request headers (incoming)
  request {
    enabled = on
    # Set headers on incoming requests
    set = {
      "X-Forwarded-By"  = "agbero"
      "X-Request-Start" = "${msec}"
    }
    # Add headers (allows duplicates)
    add = {
      "X-Trace-ID" = "${request_id}"
    }
    # Remove headers before forwarding
    remove = ["X-Powered-By", "Server", "X-AspNet-Version"]
  }

  # Response headers (outgoing)
  response {
    enabled = on
    set = {
      "X-Frame-Options"           = "SAMEORIGIN"
      "X-Content-Type-Options"    = "nosniff"
      "Strict-Transport-Security" = "max-age=31536000; includeSubDomains"
      "Referrer-Policy"           = "strict-origin-when-cross-origin"
      "Permissions-Policy"        = "geolocation=(), microphone=(), camera=()"
    }
    remove = ["Server", "X-Powered-By"]
  }
}

# -------------------------------------------------------------
# HOST-LEVEL ERROR PAGES (override global)
# -------------------------------------------------------------
# error_pages {
#   pages = {
#     "404" = "/etc/agbero/hosts/example/404.html",
#     "500" = "/etc/agbero/hosts/example/500.html",
#     "502" = "/etc/agbero/hosts/example/502.html",
#     "503" = "/etc/agbero/hosts/example/503.html"
#   }
#   default = "/etc/agbero/hosts/example/error.html"
# }

# =============================================================================
# ROUTES (path-based routing rules)
# =============================================================================

# -------------------------------------------------------------
# CATCH-ALL ROUTE: Proxy to backend pool
# -------------------------------------------------------------
route "/*" {
  enabled = on

  # Strip path prefixes before forwarding to backend
  # strip_prefixes = ["/api/v1", "/internal"]

  # URL rewriting (regex-based) - applied after strip_prefixes
  # rewrite {
  #   pattern = "^/users/(\\d+)$"
  #   target  = "/api/users?id=$1"
  # }

  # Restrict access by source IP/CIDR
  # allowed_ips = ["10.0.0.0/8", "192.168.1.0/24", "203.0.113.0/24"]

  # ---------------------------------------------------------
  # BACKEND POOL: Load-balanced proxy targets
  # ---------------------------------------------------------
  backend {
    enabled = on

    # Load balancing strategy:
    # round_robin, random, least_conn, ip_hash, url_hash,
    # weighted_least_conn, least_response_time, adaptive, sticky
    strategy = "weighted_least_conn"

    # Keys for hash-based strategies (ip_hash, url_hash, sticky)
    # keys = ["header:X-User-ID", "cookie:session_id"]

    # Backend server 1 (primary, higher weight)
    server {
      address = "http://localhost:6060"
      weight  = 2  # Receives ~2x traffic vs weight=1 servers

      # Route traffic based on source conditions (optional)
      # criteria {
      #   source_ips = ["10.0.0.0/8"]      # Only route internal IPs here
      #   headers = {"X-Region": "us-east"} # Route by header value
      # }

      # Enable streaming/WebSocket support for long-lived connections
      streaming {
        enabled        = on
        flush_interval = "100ms"  # How often to flush buffered data
      }

      # Limit concurrent connections to this backend
      # max_connections = 100
    }

    # Backend servers 2-6 (secondary, equal weight)
    server {
      address = "http://localhost:6061"
      weight  = 1
    }
    server {
      address = "http://localhost:6062"
      weight  = 1
    }
    server {
      address = "http://localhost:6063"
      weight  = 1
    }
    server {
      address = "http://localhost:6064"
      weight  = 1
    }
    server {
      address = "http://localhost:6065"
      weight  = 1
    }
  }

  # ---------------------------------------------------------
  # HEALTH CHECKS: Monitor backend availability
  # ---------------------------------------------------------
  health_check {
    enabled       = on
    path = "/health"              # Endpoint to probe
    interval = "10s"                  # How often to check
    timeout = "5s"                   # Max wait for response
    threshold = 3                     # Consecutive failures to mark unhealthy
    method = "GET"                  # HTTP method for probe
    headers = { "X-Health-Check" = "agbero" }  # Custom headers
    expected_status = [200, 204]      # Acceptable status codes
    expected_body = "OK"            # Optional body content match
  }

  # ---------------------------------------------------------
  # CIRCUIT BREAKER: Fail-fast on backend issues
  # ---------------------------------------------------------
  circuit_breaker {
    enabled  = on
    threshold = 5      # Failures to trip the breaker
    duration = "30s"  # Time in "open" state before retry
  }

  # ---------------------------------------------------------
  # ROUTE-LEVEL TIMEOUTS (override global)
  # ---------------------------------------------------------
  timeouts {
    enabled = on
    request = "60s"  # Max time waiting for backend response
  }

  # ---------------------------------------------------------
  # RATE LIMIT BYPASS (custom rules only)
  # ---------------------------------------------------------
  rate_limit {
    # Ignore global rate_limits from agbero.hcl for this route
    ignore_global = true

    # Custom rule: High-limit testing endpoint
    rule "testing" {
      enabled = on
      prefixes = ["/testing", "/debug"]
      methods = ["GET", "POST"]
      requests = 1000000  # Very high limit for testing
      window  = "1m"
      burst = 1000000  # Allow bursts up to this value
      key     = "ip"     # Track by client IP
      # Alternative keys:
      # key = "header:X-API-Key"
      # key = "cookie:session_id"
      # key = "query:api_key"
    }

    # Custom rule: Stricter limit for sensitive operations
    # rule "sensitive_ops" {
    #   enabled  = on
    #   prefixes = ["/admin", "/api/billing"]
    #   methods  = ["POST", "PUT", "DELETE"]
    #   requests = 20
    #   window   = "1m"
    #   burst    = 30
    #   key      = "ip"
    # }
  }

  # ---------------------------------------------------------
  # AUTHENTICATION (pick ONE method, or layer them)
  # ---------------------------------------------------------
  # Option 1: Basic HTTP Auth (simple username/password)
  # basic_auth {
  #   enabled = on
  #   users = [
  #     "admin:$2a$10$...",  # Generate: agbero hash -p "password"
  #     "user:$2a$10$..."
  #   ]
  #   realm = "Protected Area"
  # }

  # Option 2: JWT Auth (for API clients)
  # jwt_auth {
  #   enabled = on
  #   secret = "env.JWT_SECRET"  # or "b64.base64encoded"
  #   claims_to_headers = {
  #     "sub"   = "X-User-Id",
  #     "email" = "X-User-Email",
  #     "roles" = "X-User-Roles"
  #   }
  #   issuer   = "https://auth.example.com"
  #   audience = "example-api"
  # }

  # Option 3: Forward Auth (delegate to external auth service)
  # forward_auth {
  #   enabled = on
  #   name    = "example-auth"
  #   url     = "http://auth-service:8080/verify"
  #   timeout = "3s"
  #   on_failure = "deny"  # or "allow" to pass through on auth failure
  #
  #   request {
  #     enabled = on
  #     headers = ["Authorization", "Cookie", "X-Forwarded-For"]
  #     forward_method = true
  #     forward_uri    = true
  #     forward_ip     = true
  #     body_mode = "none"  # none, metadata, or limited
  #     max_body  = 65536
  #   }
  #
  #   response {
  #     enabled = on
  #     copy_headers = ["X-User-Id", "X-Roles", "X-Permissions"]
  #     cache_ttl = "5m"  # Cache successful auth decisions
  #   }
  # }

  # Option 4: OAuth (Google/GitHub/GitLab/OIDC for SSO)
  # oauth {
  #   enabled = on
  #   provider = "google"  # google, github, gitlab, oidc, generic
  #   client_id     = "env.OAUTH_CLIENT_ID"
  #   client_secret = "env.OAUTH_CLIENT_SECRET"
  #   redirect_url  = "https://example.localhost/oauth/callback"
  #   scopes = ["openid", "profile", "email"]
  #   cookie_secret = "env.OAUTH_COOKIE_SECRET"  # min 16 chars
  #   email_domains = ["example.com"]  # Optional: restrict to org emails
  # }

  # ---------------------------------------------------------
  # CORS (Cross-Origin Resource Sharing)
  # ---------------------------------------------------------
  cors {
    enabled = on
    allowed_origins = [
      "https://app.example.localhost",
      "https://admin.example.localhost",
      # "https://*.example.com",  # Wildcard subdomains
    ]
    allowed_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
    allowed_headers = ["Content-Type", "Authorization", "X-Requested-With", "X-API-Key"]
    exposed_headers = ["X-Request-ID", "X-RateLimit-Remaining", "X-RateLimit-Reset"]
    allow_credentials = true
    max_age           = 86400  # Preflight cache: 24 hours
  }

  # ---------------------------------------------------------
  # RESPONSE CACHING (for cacheable GET/HEAD responses)
  # ---------------------------------------------------------
  # cache {
  #   enabled = on
  #   driver  = "memory"  # memory or redis
  #   ttl     = "5m"      # Default cache duration
  #   methods = ["GET", "HEAD"]  # Only cache these HTTP methods
  #   options = {
  #     max_size_mb = "100"  # Memory driver: max cache size
  #     # Redis driver options:
  #     # host = "redis:6379"
  #     # password = "env.REDIS_PASSWORD"
  #     # db = "0"
  #     # key_prefix = "agbero:example:"
  #   }
  # }

  # ---------------------------------------------------------
  # ROUTE-LEVEL FIREWALL RULES (in addition to global)
  # ---------------------------------------------------------
  # firewall {
  #   enabled = on
  #   ignore_global = false  # Also apply global firewall rules
  #
  #   # Block common attack patterns specific to this route
  #   rule "block_admin_probe" {
  #     priority = 10
  #     type     = "dynamic"
  #     action   = "ban_short"
  #     match {
  #       path = ["/admin", "/wp-admin", "/phpmyadmin", "/.env", "/config.php"]
  #       threshold {
  #         count     = 1  # Block on first attempt
  #         window    = "1m"
  #         track_by  = "ip"
  #         on_exceed = "ban"
  #       }
  #     }
  #   }
  #
  #   # Rate-limit sensitive endpoints with extraction
  #   rule "protect_api_keys" {
  #     priority = 20
  #     type     = "dynamic"
  #     action   = "ban_short"
  #     match {
  #       path = ["/api"]
  #       methods = ["POST", "PUT", "DELETE"]
  #       extract {
  #         enabled = on
  #         from    = "header"
  #         key     = "Authorization"
  #         pattern = "^Bearer\\s+([^\\.]+)\\."  # Extract JWT prefix
  #         as      = "token_prefix"
  #       }
  #       threshold {
  #         count     = 50
  #         window    = "1m"
  #         track_by  = "extracted:token_prefix"  # Rate limit by token, not IP
  #         on_exceed = "ban"
  #       }
  #     }
  #   }
  # }

  # ---------------------------------------------------------
  # COMPRESSION (route-level override)
  # ---------------------------------------------------------
  # compression_config {
  #   enabled = on
  #   type  = "brotli"  # gzip or brotli
  #   level = 6         # 0-11: higher = better compression, slower
  # }

  # ---------------------------------------------------------
  # FALLBACK (for unmatched paths or backend failures)
  # ---------------------------------------------------------
  # fallback {
  #   enabled = on
  #   type    = "static"  # static, redirect, or proxy
  #
  #   # For type=static:
  #   status_code  = 503
  #   body         = "{\"error\": \"Service temporarily unavailable\"}"
  #   content_type = "application/json"
  #
  #   # For type=redirect:
  #   # redirect_url = "https://maintenance.example.com"
  #   # status_code  = 307
  #
  #   # For type=proxy:
  #   # proxy_url = "http://fallback-backend:8080"
  #
  #   cache_ttl = 60  # Cache fallback response for 60 seconds
  # }

  # ---------------------------------------------------------
  # WEBASSEMBLY MODULES (WASM plugins for custom logic)
  # ---------------------------------------------------------
  # wasm {
  #   enabled = on
  #   module  = "/etc/agbero/wasm/request-logger.wasm"
  #
  #   # Configuration passed to WASM module
  #   config = {
  #     "log_level" = "info",
  #     "sample_rate" = "0.1"
  #   }
  #
  #   # Max body size for WASM inspection
  #   max_body_size = 1048576  # 1MB
  #
  #   # Capabilities granted to WASM module
  #   access = ["headers", "body", "method", "uri", "config"]
  # }
}

# -------------------------------------------------------------
# STATIC ASSETS ROUTE: Cache aggressively, bypass auth
# -------------------------------------------------------------
# route "/static/*" {
#   enabled = on
#
#   # Serve files directly from filesystem (no proxy)
#   web {
#     root    = "/var/www/example/static"
#     index   = ""          # No index file for asset directories
#     listing = off         # Disable directory listing
#     spa     = off
#   }
#
#   # Aggressive caching for immutable assets
#   cache {
#     enabled = on
#     driver  = "memory"
#     ttl     = "24h"
#     methods = ["GET", "HEAD"]
#   }
#
#   # Set long-lived cache headers
#   headers {
#     response {
#       enabled = on
#       set = {
#         "Cache-Control" = "public, max-age=86400, immutable"
#       }
#     }
#   }
#
#   # Skip authentication for static assets
#   # (basic_auth, jwt_auth, etc. not configured here)
# }

# -------------------------------------------------------------
# API ROUTE: Stricter limits, different backend pool
# -------------------------------------------------------------
# route "/api/*" {
#   enabled = on
#
#   # Strip /api prefix before forwarding
#   strip_prefixes = ["/api"]
#
#   backend {
#     strategy = "least_response_time"
#     server { address = "http://api-pool-1:8080"; weight = 1 }
#     server { address = "http://api-pool-2:8080"; weight = 1 }
#   }
#
#   # Stricter rate limits for API
#   rate_limit {
#     ignore_global = false  # Apply global limits too
#     rule {
#       enabled  = on
#       prefixes = ["/api"]
#       requests = 100
#       window   = "1m"
#       key      = "header:X-API-Key"  # Rate limit by API key
#     }
#   }
#
#   # JWT auth required for API
#   jwt_auth {
#     enabled = on
#     secret = "env.API_JWT_SECRET"
#     issuer = "https://auth.example.com"
#   }
# }

# -------------------------------------------------------------
# HEALTH ENDPOINT: Allow unauthenticated health checks
# -------------------------------------------------------------
# route "/healthz" {
#   enabled = on
#
#   # Allow health checks from monitoring systems
#   allowed_ips = ["127.0.0.1", "::1", "10.0.0.0/8"]
#
#   # Proxy to backend health endpoint
#   backend {
#     server {
#       address = "http://localhost:6060/healthz"
#     }
#   }
#
#   # Skip rate limiting and auth for health endpoint
#   rate_limit { enabled = off }
#   # No auth blocks configured
# }

# =============================================================================
# TCP PROXY ROUTES (Layer 4 proxying - separate from HTTP routes)
# =============================================================================
# proxy "postgres" {
#   enabled = on
#   listen  = ":5432"                    # Listen port for TCP traffic
#   sni     = "db.example.localhost"    # Optional: route by TLS SNI
#
#   backend {
#     address = "tcp://postgres-primary:5432"
#     weight  = 1
#     max_connections = 100
#   }
#   backend {
#     address = "tcp://postgres-replica:5432"
#     weight  = 1
#   }
#
#   strategy = "least_conn"
#
#   # Send PROXY protocol header to backends (for real client IP)
#   proxy_protocol = true
#
#   # TCP-level health checks (send/expect protocol)
#   health_check {
#     enabled = on
#     interval = "5s"
#     timeout  = "2s"
#     send   = ""        # Empty = simple connect check
#     expect = ""        # Empty = any response = healthy
#     # For protocol-aware checks:
#     # send = "PING\r\n"
#     # expect = "PONG"
#   }
# }