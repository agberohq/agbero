# =============================================================================
# AGBERO - GLOBAL CONFIGURATION (agbero.hcl)
# =============================================================================
# This file is the main configuration for the agbero proxy.
# Host-specific configurations belong in {HOST_DIR}/*.hcl
# =============================================================================

# Configuration schema version
version = 1

# -------------------------------------------------------------
# BINDING ADDRESSES
# -------------------------------------------------------------
bind {
  # HTTP listeners (plain text, usually redirects to HTTPS)
  http = [":80"]

  # HTTPS/HTTP3 listeners (TLS required)
  https = [":443"]

  # Automatically redirect HTTP -> HTTPS
  redirect = "on"
}

# -------------------------------------------------------------
# ADMIN INTERFACE
# -------------------------------------------------------------
admin {
  # Enable admin UI and API endpoints
  enabled = "on"

  # Admin interface bind address
  address = ":9090"

  # Restrict admin access to specific IPs/CIDRs
  allowed_ips = ["127.0.0.1", "::1"]

  # Enable pprof debugging endpoints (security risk in prod)
  # pprof {
  #   enabled = "off"
  #   bind = "6061"
  # }

  # Telemetry for admin is enabled by default
  telemetry {
    enabled = "on"
  }

  # ---------------------------------------------------------
  # BASIC AUTH (for /login endpoint)
  # ---------------------------------------------------------
  basic_auth {
    enabled = "on"
    # Format: "username:bcrypt_hash"
    users = [
      "admin:{ADMIN_PASSWORD}"
    ]
  }

  # ---------------------------------------------------------
  # JWT AUTH (for API/programmatic access)
  # ---------------------------------------------------------
  jwt_auth {
    enabled = "on"
    # Secret for signing JWTs (base64, 16/24/32 bytes)
    secret = "{ADMIN_SECRET}"
  }

  # ---------------------------------------------------------
  # OAUTH / FORWARD AUTH (Examples)
  # ---------------------------------------------------------
  # forward_auth {
  #   enabled = "off"
  #   url     = "http://auth-service:8080/verify"
  #   request { enabled = "on" }
  #   response { enabled = "on" }
  # }
}

# -------------------------------------------------------------
# STORAGE DIRECTORIES
# -------------------------------------------------------------
storage {
  hosts_dir = "{HOST_DIR}"
  certs_dir = "{CERTS_DIR}"
  data_dir  = "{DATA_DIR}"
}

# -------------------------------------------------------------
# LOGGING
# -------------------------------------------------------------
logging {
  enabled = "on"

  # Log configuration changes on reload
  diff = "off"

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
    enabled    = "on"
    path       = "{LOGS_DIR}/agbero.log"
    batch_size = 500
    rotate_size = 52428800
  }

  # ---------------------------------------------------------
  # VICTORIALOGS INTEGRATION
  # ---------------------------------------------------------
  # victoria {
  #   enabled = "off"
  #   url = "http://localhost:9428/insert/0/prometheus/api/v1/write"
  #   batch_size = 500
  # }

  # ---------------------------------------------------------
  # PROMETHEUS METRICS ENDPOINT
  # ---------------------------------------------------------
  # prometheus {
  #   enabled = "off"
  #   path    = "/metrics"
  # }
}

# -------------------------------------------------------------
# SECURITY & FIREWALL
# -------------------------------------------------------------
security {
  enabled = "on"

  # Trusted proxy CIDRs for X-Forwarded-For resolution
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
    enabled = "on"
    mode    = "active" # active, verbose, monitor

    defaults {
      dynamic { action = "ban_short" }
      static  { action = "ban_hard" }
    }

    # Define actions referenced above
    action "ban_hard" {
      mitigation = "add"
      response {
        status_code = 403
        body_template = "{\"error\": \"Access Denied\"}"
      }
    }

    action "ban_short" {
      mitigation = "add"
      response { status_code = 429 }
    }
  }
}

# -------------------------------------------------------------
# TIMEOUTS & LIMITS
# -------------------------------------------------------------
timeouts {
  read        = "30s"
  write       = "60s"
  idle        = "120s"
  read_header = "5s"
}

general {
  max_header_bytes = 1048576
}

# -------------------------------------------------------------
# CLUSTERING (Gossip)
# -------------------------------------------------------------
gossip {
  enabled = "off"

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
# ACME / LET'S ENCRYPT
# -------------------------------------------------------------
letsencrypt {
  enabled = "{LE_ENABLED}"

  # Email for registration and expiry notifications
  email = "{LE_EMAIL}"

  # Use staging CA for testing (avoids rate limits, untrusted certs)
  staging = true

  # Request short-lived certificates (for testing/ephemeral envs)
  short_lived = false
}

# -------------------------------------------------------------
# RATE LIMITS
# -------------------------------------------------------------
rate_limits {
  enabled = "on"

  # Protect the admin login endpoint from brute force
  rule "protect_admin_login" {
    prefixes = ["/login"]
    methods  = ["POST"]
    requests = 5
    window   = "1m"
    burst    = 5
    key      = "ip"
  }
}