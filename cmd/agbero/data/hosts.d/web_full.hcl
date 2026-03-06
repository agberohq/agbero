# =============================================================================
# WEB HOST CONFIGURATION TEMPLATE
# File: hosts.d/web.hcl
# Purpose: Serve static files, PHP, or proxy to backend
# =============================================================================

# Domains this host responds to (wildcards supported)
domains = [
"localhost",
"www.localhost",
# "example.com",
# "*.example.com",  # matches sub.example.com but not example.com
]

# Optional: Override global bind ports for this host only
# bind = ["8080", "8443"]

# Custom 404 page for this host (optional)
# not_found_page = "/etc/agbero/hosts/web/404.html"

# Enable compression for responses (gzip/brotli)
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
#   cert_file = "/etc/ssl/certs/localhost.crt"
#   key_file  = "/etc/ssl/private/localhost.key"
# }

# For mode = "letsencrypt": override global settings
# letsencrypt {
#   enabled = on
#   email   = "web@example.com"
#   staging = false
# }

# For mode = "custom_ca": use internal CA
# custom_ca {
#   enabled = on
#   root    = "/etc/ssl/ca/root-ca.crt"
# }

# Client certificate authentication (optional)
# client_auth = "require_and_verify"  # none, request, require, verify_if_given, require_and_verify
# client_cas = ["/etc/ssl/ca/client-ca.crt"]
}

# -------------------------------------------------------------
# REQUEST LIMITS (per-host)
# -------------------------------------------------------------
limits {
# Maximum request body size in bytes (default: 2MB)
max_body_size = 10485760  # 10MB
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
"X-Forwarded-By" = "agbero"
}
# Add headers (allows duplicates)
add = {
"X-Trace-ID" = "${request_id}"
}
# Remove headers
remove = ["X-Powered-By", "Server"]
}

# Response headers (outgoing)
response {
enabled = on
set = {
"X-Frame-Options"           = "DENY"
"X-Content-Type-Options"    = "nosniff"
"Strict-Transport-Security" = "max-age=31536000; includeSubDomains"
"Referrer-Policy"           = "strict-origin-when-cross-origin"
}
remove = ["Server", "X-Powered-By"]
}
}

# -------------------------------------------------------------
# HOST-LEVEL ERROR PAGES (override global)
# -------------------------------------------------------------
# error_pages {
#   pages = {
#     "404" = "/etc/agbero/hosts/web/404.html",
#     "500" = "/etc/agbero/hosts/web/500.html",
#     "502" = "/etc/agbero/hosts/web/502.html"
#   }
#   default = "/etc/agbero/hosts/web/error.html"
# }

# =============================================================================
# ROUTES (path-based routing rules)
# =============================================================================

# -------------------------------------------------------------
# ROOT ROUTE: Serve static files with optional PHP
# -------------------------------------------------------------
route "/" {
enabled = on

# Strip path prefixes before forwarding (for proxy routes only)
# strip_prefixes = ["/api/v1"]

# URL rewriting (regex-based)
# rewrite {
#   pattern = "^/users/(\\d+)$"
#   target  = "/api/users?id=$1"
# }

# Restrict access by source IP/CIDR
# allowed_ips = ["10.0.0.0/8", "192.168.1.0/24"]

# ---------------------------------------------------------
# WEB BLOCK: Serve static files from filesystem
# ---------------------------------------------------------
web {
enabled = on
root    = "/var/www/example.com/public"  # or "." for current dir
index   = "index.html"                    # default index file
listing = off                             # enable directory listing
spa     = off                             # single-page app mode (fallback to index.html)

# PHP-FPM integration (optional)
php {
enabled = on
# Unix socket: "unix:/run/php/php-fpm.sock"
# TCP: "127.0.0.1:9000"
address = "127.0.0.1:9000"
index   = "index.php"
}
}

# ---------------------------------------------------------
# AUTHENTICATION (route-level)
# ---------------------------------------------------------
# basic_auth {
#   enabled = on
#   users = ["user:$2a$10$..."]  # Generate: agbero hash -p "password"
#   realm = "Protected Area"
# }
#
# jwt_auth {
#   enabled = on
#   secret = "env.JWT_SECRET"  # or "b64.base64encoded"
#   claims_to_headers = {"sub": "X-User-ID"}
#   issuer = "https://auth.example.com"
# }
#
# forward_auth {
#   enabled = on
#   url   = "http://auth-service:8080/verify"
#   timeout = "5s"
#   on_failure = "deny"  # or "allow"
#   request {
#     headers = ["Authorization", "Cookie"]
#     forward_method = true
#     forward_uri    = true
#     forward_ip     = true
#     body_mode = "none"  # none, metadata, limited
#   }
#   response {
#     copy_headers = ["X-User-Id", "X-Roles"]
#     cache_ttl = "5m"
#   }
# }
#
# oauth {
#   enabled = on
#   provider = "google"  # google, github, gitlab, oidc, generic
#   client_id     = "your-client-id"
#   client_secret = "env.OAUTH_CLIENT_SECRET"
#   redirect_url  = "https://example.com/oauth/callback"
#   scopes = ["openid", "profile", "email"]
#   cookie_secret = "env.OAUTH_COOKIE_SECRET"  # min 16 chars
#   email_domains = ["example.com"]  # optional restriction
# }

# ---------------------------------------------------------
# CORS (Cross-Origin Resource Sharing)
# ---------------------------------------------------------
# cors {
#   enabled = on
#   allowed_origins   = ["https://app.example.com", "https://admin.example.com"]
#   allowed_methods   = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
#   allowed_headers   = ["Content-Type", "Authorization", "X-Requested-With"]
#   exposed_headers   = ["X-Request-ID", "X-RateLimit-Remaining"]
#   allow_credentials = true
#   max_age           = 86400  # Preflight cache in seconds
# }

# ---------------------------------------------------------
# RESPONSE CACHING
# ---------------------------------------------------------
# cache {
#   enabled = on
#   driver  = "memory"  # memory, redis
#   ttl     = "5m"
#   methods = ["GET", "HEAD"]
#   options = {
#     max_size_mb = "100"  # For memory driver
#     # host = "redis:6379"  # For redis driver
#     # password = "env.REDIS_PASSWORD"
#     # db = "0"
#     # key_prefix = "agbero:cache:"
#   }
# }

# ---------------------------------------------------------
# ROUTE-LEVEL RATE LIMITING
# ---------------------------------------------------------
# rate_limit {
#   enabled = on
#   ignore_global = false  # Apply global rate limits too
#   use_policy = "strict"  # Use named policy from global config
#
#   # Or define ad-hoc rule
#   rule {
#     enabled = on
#     name    = "api_burst"
#     prefixes = ["/api/bursty"]
#     methods = ["POST"]
#     requests = 20
#     window   = "1m"
#     burst    = 30
#     key      = "header:Authorization"  # ip, header:Name, cookie:Name, query:Name
#   }
# }

# ---------------------------------------------------------
# ROUTE-LEVEL FIREWALL RULES
# ---------------------------------------------------------
# firewall {
#   enabled = on
#   ignore_global = false
#   apply_rules = ["block_sqli", "protect_login"]
#
#   # Route-specific rules (same syntax as global firewall)
#   rule "block_admin_probe" {
#     type = "dynamic"
#     action = "ban_short"
#     match {
#       path = ["/admin", "/wp-admin", "/phpmyadmin"]
#       threshold {
#         count = 1
#         window = "1m"
#         track_by = "ip"
#       }
#     }
#   }
# }

# ---------------------------------------------------------
# COMPRESSION (route-level override)
# ---------------------------------------------------------
# compression_config {
#   enabled = on
#   type  = "gzip"    # gzip, brotli
#   level = 5         # 0-11 (higher = better compression, slower)
# }

# ---------------------------------------------------------
# FALLBACK (route-level)
# ---------------------------------------------------------
# fallback {
#   enabled = on
#   type    = "static"  # static, redirect, proxy
#   status_code  = 404
#   body         = "{\"error\": \"Not Found\"}"
#   content_type = "application/json"
# }

# ---------------------------------------------------------
# WEBASSEMBLY MODULES (WASM plugins)
# ---------------------------------------------------------
# wasm {
#   enabled = on
#   module  = "/etc/agbero/wasm/my-plugin.wasm"
#   config = {
#     "api_key" = "env.PLUGIN_API_KEY",
#     "timeout" = "5000"
#   }
#   max_body_size = 1048576
#   access = ["headers", "body", "method", "uri", "config"]
# }
}

# -------------------------------------------------------------
# API ROUTE: Proxy to backend service
# -------------------------------------------------------------
# route "/api" {
#   enabled = on
#
#   backend {
#     enabled = on
#     strategy = "round_robin"  # random, least_conn, ip_hash, url_hash, weighted_least_conn, adaptive, sticky
#     keys = ["header:X-User-ID", "cookie:session"]  # For hash-based strategies
#
#     server {
#       address = "http://backend-1:8080"
#       weight  = 1
#
#       # Route traffic based on source conditions
#       # criteria {
#       #   source_ips = ["10.0.0.0/8"]
#       #   headers = {"X-Region": "us-east"}
#       # }
#
#       # Streaming/WebSocket support
#       streaming {
#         enabled = on
#         flush_interval = "100ms"
#       }
#
#       # Max concurrent connections to this backend
#       # max_connections = 100
#     }
#
#     server {
#       address = "http://backend-2:8080"
#       weight  = 2  # Higher weight = more traffic
#     }
#   }
#
#   # Health checks for backend servers
#   health_check {
#     enabled = on
#     path    = "/health"
#     interval = "10s"
#     timeout  = "5s"
#     threshold = 3  # Consecutive failures to mark unhealthy
#     method   = "GET"
#     headers  = {"X-Health-Check": "agbero"}
#     expected_status = [200, 204]
#     expected_body   = "OK"
#   }
#
#   # Circuit breaker (fail-fast on backend issues)
#   circuit_breaker {
#     enabled = on
#     threshold = 5     # Failures to trip
#     duration  = "30s" # Time in open state before retry
#   }
#
#   # Route-level timeouts
#   timeouts {
#     enabled = on
#     request = "30s"  # Max time for backend response
#   }
# }

# -------------------------------------------------------------
# CATCH-ALL ROUTE: Must be last (longest path match wins)
# -------------------------------------------------------------
# route "/*" {
#   enabled = on
#   web {
#     root = "/var/www/example.com/public"
#     spa  = on  # Fallback to index.html for SPA routing
#   }
# }

# =============================================================================
# TCP PROXY ROUTES (Layer 4 proxying - separate from HTTP routes)
# =============================================================================
# proxy "postgres" {
#   enabled = on
#   listen  = ":5432"
#   sni     = "db.localhost"  # For TLS SNI-based routing (optional)
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
#   # Send PROXY protocol header to backends
#   proxy_protocol = true
#
#   # TCP health checks (send/expect for protocol-level checks)
#   health_check {
#     enabled = on
#     interval = "5s"
#     timeout  = "2s"
#     send   = "PING\r\n"
#     expect = "PONG"
#   }
# }