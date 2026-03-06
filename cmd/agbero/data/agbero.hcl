# =============================================================================
# AGBERO - GLOBAL CONFIGURATION TEMPLATE (agbero.hcl)
# =============================================================================
# This file is the main configuration for the agbero proxy.
# Host-specific configurations belong in {HOST_DIR}/*.hcl
#
# Placeholders (replaced during 'agbero init'):
#   {HOST_DIR}     -> hosts.d
#   {CERTS_DIR}    -> certs.d
#   {DATA_DIR}     -> data.d
#   {LOGS_DIR}     -> logs.d
#   {ADMIN_PASSWORD} -> bcrypt hash of generated password
#   {ADMIN_SECRET}   -> base64-encoded JWT secret
# =============================================================================

# -------------------------------------------------------------
# GLOBAL SETTINGS
# -------------------------------------------------------------
# Configuration schema version (do not change unless migrating)
version = 2

# Enable development mode: debug logging, verbose errors, relaxed TLS
# WARNING: Disable for production
development = false


# -------------------------------------------------------------
# BINDING ADDRESSES
# -------------------------------------------------------------
bind {
  # HTTP listeners (plain text, may redirect to HTTPS)
  # Format: ":port" or "host:port" (e.g., ":80", "0.0.0.0:8080", "[::]:80")
  http = [":80"]

  # HTTPS/HTTP3 listeners (TLS required)
  https = [":443"]

  # Automatically redirect HTTP -> HTTPS
  # Values: on, off, unknown (auto)
  redirect = on
}


# -------------------------------------------------------------
# ADMIN INTERFACE
# -------------------------------------------------------------
admin {
  # Enable admin UI and API endpoints
  # Values: on, off, unknown (auto-enabled if address set)
  enabled = on

  # Enable pprof debugging endpoints at /debug/pprof
  # SECURITY: Restrict via allowed_ips in production
  pprof = off

  # Admin interface bind address (required if enabled)
  address = ":9090"

  # Restrict admin access to specific IPs/CIDRs
  # Empty = allow all (requires auth)
  allowed_ips = ["127.0.0.1", "::1"]

  # ---------------------------------------------------------
  # BASIC AUTH (for /login endpoint)
  # ---------------------------------------------------------
  basic_auth {
    enabled = on

    # Format: "username:bcrypt_hash"
    # Generate hash: agbero hash -p "your_password"
    users = [
      "admin:{ADMIN_PASSWORD}"
    ]

    # HTTP Basic Auth realm (default: "Restricted")
    # realm = "Admin Area"
  }

  # ---------------------------------------------------------
  # JWT AUTH (for API/programmatic access)
  # ---------------------------------------------------------
  jwt_auth {
    enabled = on

    # Secret for signing JWTs (base64, 16/24/32 bytes decoded)
    # Generate: agbero key init
    secret = "{ADMIN_SECRET}"

    # Map JWT claims to HTTP headers (claim -> header)
    # claims_to_headers = {
    #   "sub" = "X-User-Id",
    #   "email" = "X-User-Email"
    # }

    # Require specific issuer/audience (optional)
    # issuer = "agbero-admin"
    # audience = "admin-api"
  }

  # ---------------------------------------------------------
  # FORWARD AUTH (delegate to external auth service)
  # ---------------------------------------------------------
  # forward_auth {
  #   enabled = off
  #   name    = "external-auth"
  #   url     = "http://auth-service:8080/verify"
  #
  #   tls {
  #     enabled = off
  #     insecure_skip_verify = false
  #     # client_cert = "env.TLS_CLIENT_CERT"
  #     # client_key  = "env.TLS_CLIENT_KEY"
  #     # ca          = "env.TLS_CA_CERT"
  #   }
  #
  #   request {
  #     enabled = on
  #     headers = ["Authorization", "Cookie"]
  #     forward_method = true
  #     forward_uri    = true
  #     forward_ip     = true
  #     body_mode = "none"  # none, metadata, limited
  #     max_body  = 65536
  #     cache_key = ["Authorization"]
  #   }
  #
  #   response {
  #     enabled = on
  #     copy_headers = ["X-User-Id", "X-Roles"]
  #     cache_ttl = "5m"
  #   }
  #
  #   on_failure = "deny"  # allow or deny
  #   timeout    = "5s"
  # }

  # ---------------------------------------------------------
  # OAUTH (Google, GitHub, GitLab, OIDC)
  # ---------------------------------------------------------
  # oauth {
  #   enabled = off
  #   provider = "google"  # google, github, gitlab, oidc, generic
  #
  #   client_id     = "your-client-id"
  #   client_secret = "env.OAUTH_CLIENT_SECRET"
  #   redirect_url  = "https://your-domain.com/oauth/callback"
  #
  #   # OIDC/Generic only:
  #   # auth_url    = "https://idp.example.com/oauth/authorize"
  #   # token_url   = "https://idp.example.com/oauth/token"
  #   # user_api_url = "https://idp.example.com/oauth/userinfo"
  #
  #   scopes = ["openid", "profile", "email"]
  #   cookie_secret = "env.OAUTH_COOKIE_SECRET"  # min 16 chars
  #   # email_domains = ["example.com"]
  # }
}


# -------------------------------------------------------------
# API ENDPOINTS (Internal Service API)
# -------------------------------------------------------------
# api {
#   enabled = off
#   address = ":9091"
#   allowed_ips = ["127.0.0.1/32", "10.0.0.0/8"]
# }


# -------------------------------------------------------------
# STORAGE DIRECTORIES
# -------------------------------------------------------------
storage {
  # Directory for host/route .hcl files (relative to config dir)
  hosts_dir = "{HOST_DIR}"

  # Directory for TLS certificates (auto-created)
  certs_dir = "{CERTS_DIR}"

  # Data directory for persistent state (firewall, etc.)
  data_dir = "{DATA_DIR}"
}


# -------------------------------------------------------------
# LOGGING CONFIGURATION
# -------------------------------------------------------------
logging {
  # Global logging enable
  enabled = on

  # Log configuration changes on reload
  diff = off

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
    enabled = on
    path    = "{LOGS_DIR}/agbero.log"
    batch_size = 500  # Entries to batch before flush
  }

  # ---------------------------------------------------------
  # VICTORIALOGS INTEGRATION
  # ---------------------------------------------------------
  # victoria {
  #   enabled = off
  #   url = "http://localhost:9428/insert/0/prometheus/api/v1/write"
  #   batch_size = 500
  # }

  # ---------------------------------------------------------
  # PROMETHEUS METRICS ENDPOINT
  # ---------------------------------------------------------
  prometheus {
    enabled = off
    path    = "/metrics"
  }
}


# -------------------------------------------------------------
# SECURITY SETTINGS
# -------------------------------------------------------------
security {
  # Enable security features (firewall, internal auth, etc.)
  enabled = on

  # Trusted proxy CIDRs for X-Forwarded-* header processing
  trusted_proxies = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "::1/128"
  ]

  # Path to internal auth key for service-to-service authentication
  # Generate: agbero key init
  # internal_auth_key = "/etc/agbero/internal_auth.key"

  # ---------------------------------------------------------
  # APPLICATION FIREWALL / WAF
  # ---------------------------------------------------------
  firewall {
    enabled = on
    mode    = "active"  # active, verbose, monitor

    # Body inspection settings
    inspect_body = true
    max_inspect_bytes = 8192
    inspect_content_types = [
      "application/json",
      "application/xml",
      "application/x-www-form-urlencoded",
      "text/plain",
      "multipart/form-data"
    ]

    # Default actions for rule types
    defaults {
      dynamic {
        action   = "ban_short"
        duration = "1h"
      }
      static {
        action   = "ban_hard"
        duration = "8760h"
      }
    }

    # ---------------------------------------------------------
    # CUSTOM ACTIONS
    # ---------------------------------------------------------
    action "ban_hard" {
      mitigation = "add"
      response {
        enabled      = on
        status_code  = 403
        content_type = "application/json"
        body_template = "{\"error\": \"Access Denied\", \"rule\": \"{{.RuleName}}\"}"
        # headers = { "X-Blocked-By" = "agbero" }
      }
    }

    action "ban_short" {
      mitigation = "add"
      response {
        enabled      = on
        status_code  = 429
        body_template = "Too many requests. Triggered: {{.RuleName}}"
      }
    }

    action "log_only" {
      mitigation = "none"
      logging {
        enabled = on
        level   = "warn"
      }
    }

    # ---------------------------------------------------------
    # FIREWALL RULES
    # ---------------------------------------------------------
    # Rule types: static (immediate), dynamic (threshold), whitelist

    # Whitelist trusted internal monitoring
    rule "allow_internal_monitoring" {
      priority = 5
      type     = "whitelist"
      match {
        enabled = on
        any {
          location = "ip"
          value    = "10.0.0.50"
        }
        any {
          location = "header"
          key      = "X-Internal-Secret"
          value    = "SuperSecretKey"
        }
      }
    }

    # Block known malicious IPs
    rule "global_blacklist" {
      priority = 10
      type     = "static"
      action   = "ban_hard"
      match {
        enabled = on
        ip = ["1.2.3.4", "5.6.7.0/24"]
      }
    }

    # SQL Injection pattern detection
    rule "block_sqli" {
      priority = 20
      type     = "dynamic"
      action   = "ban_hard"
      match {
        enabled = on
        any {
          location = "body"
          pattern  = "(?i)(union\\s+select|select\\s+.*\\s+from|drop\\s+table)"
        }
        any {
          location = "query"
          pattern  = "(?i)(union\\s+select|select\\s+.*\\s+from)"
        }
        any {
          location = "path"
          pattern  = "(?i)(\\.\\./|%2e%2e)"
        }
      }
    }

    # Login brute force protection
    rule "protect_login" {
      priority = 30
      type     = "dynamic"
      action   = "ban_short"
      match {
        enabled = on
        path    = ["/login", "/auth", "/api/auth"]
        methods = ["POST"]
        threshold {
          enabled   = on
          count     = 5
          window    = "1m"
          track_by  = "ip"  # ip, header:Name, cookie:Name
          on_exceed = "ban"
        }
      }
    }

    # Block suspicious User-Agents
    rule "bad_bots" {
      priority = 40
      type     = "dynamic"
      action   = "ban_hard"
      match {
        enabled = on
        any {
          location    = "header"
          key         = "User-Agent"
          operator    = "contains"
          value       = "sqlmap"
          ignore_case = true
        }
        any {
          location    = "header"
          key         = "User-Agent"
          operator    = "contains"
          value       = "nikto"
          ignore_case = true
        }
        any {
          location = "header"
          key      = "User-Agent"
          operator = "empty"
        }
      }
    }

    # Rate-based path protection with extraction
    # rule "api_abuse" {
    #   priority = 50
    #   type     = "dynamic"
    #   action   = "ban_short"
    #   match {
    #     enabled = on
    #     path    = ["/api/"]
    #     methods = ["POST", "PUT", "DELETE"]
    #     extract {
    #       enabled = on
    #       from    = "header"
    #       key     = "Authorization"
    #       pattern = "^Bearer\\s+([^\\.]+)\\."
    #       as      = "user_token_prefix"
    #     }
    #     threshold {
    #       enabled   = on
    #       count     = 100
    #       window    = "1m"
    #       track_by  = "header:Authorization"
    #       on_exceed = "ban"
    #     }
    #   }
    # }
  }
}


# -------------------------------------------------------------
# GENERAL SERVER TWEAKS
# -------------------------------------------------------------
general {
  # Maximum request header size in bytes (default: 1MB)
  max_header_bytes = 1048576
}


# -------------------------------------------------------------
# GLOBAL TIMEOUTS
# -------------------------------------------------------------
timeouts {
  enabled = on

  read        = "30s"   # Max time to read request body
  write       = "60s"   # Max time to write response
  idle        = "120s"  # Keep-alive connection timeout
  read_header = "5s"    # Max time to read request headers
}


# -------------------------------------------------------------
# GLOBAL RATE LIMITING
# -------------------------------------------------------------
rate_limits {
  enabled     = on
  ttl         = "30m"       # TTL for rate limit entries
  max_entries = 100000      # Max unique keys to track

  # High-value endpoints: strict limits
  rule "payment" {
    enabled  = on
    prefixes = ["/api/checkout", "/api/payment", "/api/billing"]
    methods  = ["POST", "PUT", "DELETE"]
    requests = 5
    window   = "1m"
    burst    = 10           # Allow short bursts
    key      = "ip"         # Track by: ip, header:Name, cookie:Name
  }

  # Authentication endpoints
  rule "auth_limit" {
    enabled  = on
    prefixes = ["/login", "/auth", "/admin", "/api/auth"]
    requests = 10
    window   = "1m"
    key      = "ip"
  }

  # General API: higher limits with API key tracking
  rule "general_api" {
    enabled  = on
    prefixes = ["/api"]
    requests = 1000
    window   = "1m"
    key      = "header:X-API-Key"
  }

  # Catch-all default rule (must be last)
  rule "global" {
    enabled  = on
    requests = 5000
    window   = "1m"
    key      = "ip"
  }

  # ---------------------------------------------------------
  # NAMED POLICIES (reusable across routes)
  # ---------------------------------------------------------
  # policy "strict" {
  #   requests = 10
  #   window   = "1m"
  #   burst    = 15
  #   key      = "ip"
  # }
  #
  # policy "moderate" {
  #   requests = 100
  #   window   = "1m"
  #   burst    = 150
  #   key      = "header:X-User-ID"
  # }
}


# -------------------------------------------------------------
# CLUSTERING / GOSSIP PROTOCOL
# -------------------------------------------------------------
gossip {
  # Enable cluster mode for config synchronization
  enabled = off

  # Gossip protocol port (default: 7946)
  port = 7946

  # Secret key for encrypting gossip traffic (16, 24, or 32 bytes decoded)
  # Generate: agbero cluster secret
  # secret_key = "b64.xVZ9k2mN8pQrS4tU6vW8xY0zA1bC3dE5fG7hI9jK="

  # Initial seed nodes to join (host:port format)
  # seeds = ["10.0.0.2:7946", "10.0.0.3:7946"]

  # TTL for cluster route entries in seconds
  # ttl = 30
}


# -------------------------------------------------------------
# ACME / LET'S ENCRYPT AUTOMATION
# -------------------------------------------------------------
letsencrypt {
  enabled = on

  # Email for registration and expiry notifications
  email = "admin@example.com"

  # Use staging CA for testing (avoids rate limits, untrusted certs)
  staging = false

  # Request short-lived certificates (for testing/ephemeral envs)
  short_lived = false
}


# -------------------------------------------------------------
# GLOBAL FALLBACK RESPONSE (for unmatched requests)
# -------------------------------------------------------------
# fallback {
#   enabled = off
#   type    = "static"  # static, redirect, proxy
#
#   # For type=static:
#   status_code  = 503
#   body         = "{\"error\": \"Service temporarily unavailable\"}"
#   content_type = "application/json"
#
#   # For type=redirect:
#   # redirect_url = "https://maintenance.example.com"
#
#   # For type=proxy:
#   # proxy_url = "http://fallback-backend:8080"
#
#   cache_ttl = 60  # Cache fallback response (seconds)
# }


# -------------------------------------------------------------
# GLOBAL ERROR PAGES
# -------------------------------------------------------------
# error_pages {
#   pages = {
#     "404" = "/etc/agbero/errors/404.html",
#     "500" = "/etc/agbero/errors/500.html",
#     "502" = "/etc/agbero/errors/502.html",
#     "503" = "/etc/agbero/errors/503.html"
#   }
#   default = "/etc/agbero/errors/default.html"
# }


# =============================================================================
# QUICK REFERENCE
# =============================================================================
#
# ENABLED VALUES:
#   on, true, enabled, yes, 1     -> Active
#   off, false, disabled, no, -1  -> Inactive
#   unknown, default, 0           -> Auto-detect / inherit
#
# TIME DURATIONS: "100ms", "1s", "1m", "1h", "24h", "7d", "30d"
# BYTES: Plain integers (1048576 = 1MB)
# IPs: "192.168.1.100", "::1", "10.0.0.0/8", "192.168.0.0/16"
# URLS: "http://host:port", "https://host:port", "tcp://host:port", "unix:/path.sock"
#
# ENVIRONMENT VARIABLES:
#   "env.MY_VAR", "b64.base64encodedvalue"
#
# FIREWALL MATCH LOCATIONS: ip, path, uri, method, header, query, body
# FIREWALL OPERATORS: equals (default), contains, prefix, suffix, empty, missing, regex
#
# LOAD BALANCING STRATEGIES:
#   round_robin, random, least_conn, ip_hash, url_hash,
#   weighted_least_conn, least_response_time, adaptive, sticky
#
# =============================================================================