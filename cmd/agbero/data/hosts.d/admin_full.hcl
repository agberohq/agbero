# =============================================================================
# ADMIN HOST CONFIGURATION TEMPLATE
# File: hosts.d/admin.hcl
# Purpose: Secure admin interface with proxy, auth, and rate limiting
# =============================================================================

domains = [
  "admin.localhost",
  # "admin.example.com",
]

# Optional: Bind to specific port only
# bind = ["9090"]

compression = true

# -------------------------------------------------------------
# TLS SETTINGS
# -------------------------------------------------------------
tls {
  mode = "auto"
  # For production, consider:
  # mode = "letsencrypt"
  # letsencrypt {
  #   email = "admin@example.com"
  #   staging = false
  # }
}

# -------------------------------------------------------------
# REQUEST LIMITS (stricter for admin)
# -------------------------------------------------------------
limits {
  max_body_size = 1048576  # 1MB max for admin uploads
}

# -------------------------------------------------------------
# SECURITY HEADERS
# -------------------------------------------------------------
headers {
  enabled = on
  response {
    enabled = on
    set = {
      "X-Frame-Options"           = "DENY"
      "X-Content-Type-Options"    = "nosniff"
      "Strict-Transport-Security" = "max-age=31536000; includeSubDomains; preload"
      "Content-Security-Policy"   = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'"
      "Referrer-Policy"           = "strict-origin"
      "Permissions-Policy"        = "geolocation=(), microphone=(), camera=()"
    }
    remove = ["Server", "X-Powered-By", "X-AspNet-Version"]
  }
}

# -------------------------------------------------------------
# ERROR PAGES (admin-specific)
# -------------------------------------------------------------
# error_pages {
#   pages = {
#     "401" = "/etc/agbero/hosts/admin/401.html",
#     "403" = "/etc/agbero/hosts/admin/403.html",
#     "500" = "/etc/agbero/hosts/admin/500.html"
#   }
#   default = "/etc/agbero/hosts/admin/error.html"
# }

# =============================================================================
# ROUTES
# =============================================================================

# -------------------------------------------------------------
# DEFAULT ROUTE: Proxy to admin backend service
# -------------------------------------------------------------
route "/" {
  enabled = on

  # Route-level timeouts (longer for admin operations)
  timeouts {
    enabled = on
    request = "60s"
  }

  # Proxy to admin backend
  backend {
    enabled = on
    strategy = "round_robin"

    server {
      address = "http://127.0.0.1:9090"  # Admin service port
      weight  = 1

      # Enable streaming for long-running admin operations
      streaming {
        enabled = on
        flush_interval = "500ms"
      }

      # Limit concurrent connections to admin backend
      max_connections = 50
    }
  }

  # Health check for admin backend
  health_check {
    enabled = on
    path    = "/healthz"
    interval = "15s"
    timeout  = "5s"
    threshold = 2
    method   = "GET"
    expected_status = [200]
  }

  # Circuit breaker for admin backend
  circuit_breaker {
    enabled = on
    threshold = 3
    duration  = "60s"
  }

  # ---------------------------------------------------------
  # IP RESTRICTION (admin access only from localhost/internal)
  # ---------------------------------------------------------
  allowed_ips = [
    "127.0.0.1",
    "::1",
    # "10.0.0.0/8",      # Internal network
    # "192.168.1.0/24",  # Office network
  ]

  # ---------------------------------------------------------
  # AUTHENTICATION (layered security)
  # ---------------------------------------------------------
  # Option 1: Basic Auth (simple)
  # basic_auth {
  #   enabled = on
  #   users = [
  #     "admin:$2a$10$..."  # Generate: agbero hash -p "password"
  #   ]
  #   realm = "Admin Area"
  # }

  # Option 2: JWT Auth (for API clients)
  # jwt_auth {
  #   enabled = on
  #   secret = "env.ADMIN_JWT_SECRET"
  #   claims_to_headers = {
  #     "sub"   = "X-Admin-Id",
  #     "email" = "X-Admin-Email",
  #     "roles" = "X-Admin-Roles"
  #   }
  #   issuer = "agbero-admin"
  #   audience = "admin-api"
  # }

  # Option 3: Forward Auth (delegate to external auth service)
  # forward_auth {
  #   enabled = on
  #   name    = "admin-auth"
  #   url     = "http://auth-service:8080/verify?scope=admin"
  #   timeout = "3s"
  #   on_failure = "deny"
  #   request {
  #     headers = ["Authorization", "Cookie", "X-Forwarded-For"]
  #     forward_method = true
  #     forward_uri    = true
  #     forward_ip     = true
  #     body_mode = "metadata"
  #   }
  #   response {
  #     copy_headers = ["X-Admin-Id", "X-Admin-Roles", "X-Admin-Permissions"]
  #     cache_ttl = "10m"
  #   }
  # }

  # Option 4: OAuth (Google/GitHub/GitLab for SSO)
  # oauth {
  #   enabled = on
  #   provider = "google"  # google, github, gitlab, oidc
  #   client_id     = "env.ADMIN_OAUTH_CLIENT_ID"
  #   client_secret = "env.ADMIN_OAUTH_CLIENT_SECRET"
  #   redirect_url  = "https://admin.example.com/oauth/callback"
  #   scopes = ["openid", "profile", "email"]
  #   cookie_secret = "env.ADMIN_OAUTH_COOKIE_SECRET"
  #   email_domains = ["example.com", "corp.example.com"]  # Restrict to org emails
  # }

  # ---------------------------------------------------------
  # STRICT RATE LIMITING (prevent brute force)
  # ---------------------------------------------------------
  rate_limit {
    enabled = on
    ignore_global = true  # Use only route-specific limits

    rule {
      enabled = on
      name    = "admin_strict"
      prefixes = ["/"]
      methods = ["POST", "PUT", "DELETE", "PATCH"]  # Write operations
      requests = 10
      window   = "1m"
      burst    = 15
      key      = "ip"  # Track by client IP
    }

    rule {
      enabled = on
      name    = "admin_login"
      prefixes = ["/login", "/auth"]
      methods = ["POST"]
      requests = 3
      window   = "5m"
      burst    = 5
      key      = "ip"
    }
  }

  # ---------------------------------------------------------
  # FIREWALL RULES (admin-specific protection)
  # ---------------------------------------------------------
  firewall {
    enabled = on
    ignore_global = false  # Also apply global firewall rules

    # Block common admin attack patterns
    rule "block_admin_scanners" {
      priority = 10
      type     = "dynamic"
      action   = "ban_hard"
      match {
        any {
          location = "path"
          pattern  = "(?i)(/admin|/wp-admin|/phpmyadmin|/\.env|/config\.php)"
        }
        any {
          location = "header"
          key      = "User-Agent"
          operator = "contains"
          value    = "sqlmap"
          ignore_case = true
        }
        any {
          location = "header"
          key      = "User-Agent"
          operator = "empty"
        }
      }
    }

    # Rate-limit sensitive endpoints
    rule "protect_admin_actions" {
      priority = 20
      type     = "dynamic"
      action   = "ban_short"
      match {
        path = ["/api/users", "/api/config", "/api/logs"]
        methods = ["POST", "PUT", "DELETE"]
        threshold {
          count     = 5
          window    = "1m"
          track_by  = "ip"
          on_exceed = "ban"
        }
      }
    }
  }

  # ---------------------------------------------------------
  # CORS (restrict admin API access)
  # ---------------------------------------------------------
  # cors {
  #   enabled = on
  #   allowed_origins   = ["https://admin.example.com"]
  #   allowed_methods   = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
  #   allowed_headers   = ["Content-Type", "Authorization", "X-Requested-With"]
  #   exposed_headers   = ["X-Request-ID"]
  #   allow_credentials = true
  #   max_age           = 3600
  # }

  # ---------------------------------------------------------
  # CACHE (disable caching for admin dynamic content)
  # ---------------------------------------------------------
  # cache {
  #   enabled = off  # Admin content should not be cached
  # }
}

# -------------------------------------------------------------
# STATIC ASSETS ROUTE: Cache aggressively
# -------------------------------------------------------------
# route "/static" {
#   enabled = on
#   web {
#     root = "/var/www/admin/static"
#     listing = off
#   }
#   cache {
#     enabled = on
#     driver  = "memory"
#     ttl     = "24h"
#     methods = ["GET", "HEAD"]
#   }
#   headers {
#     response {
#       enabled = on
#       set = {
#         "Cache-Control" = "public, max-age=86400, immutable"
#       }
#     }
#   }
# }

# -------------------------------------------------------------
# HEALTH ENDPOINT: Allow unauthenticated health checks
# -------------------------------------------------------------
# route "/healthz" {
#   enabled = on
#   allowed_ips = ["127.0.0.1", "::1", "10.0.0.0/8"]  # Internal only
#   backend {
#     server {
#       address = "http://127.0.0.1:9090/healthz"
#     }
#   }
#   # Skip auth and rate limiting for health endpoint
#   rate_limit {
#     enabled = off
#   }
# }