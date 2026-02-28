# Agbero Full Configuration Reference

# -------------------------------------------------------------
# GLOBAL SETTINGS
# -------------------------------------------------------------
# Configuration version
version = 2

# Enable detailed logs and development features (disable for production)
development = false

# -------------------------------------------------------------
# BINDING ADDRESSES
# -------------------------------------------------------------
bind {
  # List of addresses to listen for HTTP traffic (redirects to HTTPS if configured)
  http = [":80"]

  # List of addresses to listen for HTTPS/HTTP3 traffic
  https = [":443"]
}


# -------------------------------------------------------------
# ADMIN
# -------------------------------------------------------------
admin {
  # enable
  enabled = 1

  # pprof
  pprof = 1

  # allowed ip
  allowed_ips = ["127.0.0.1", "::1"]

  # List of addresses to listen for HTTP traffic (redirects to HTTPS if configured)
  address = ":9090"

  # Basic Auth for the Login API
  basic_auth {
    # enable
    enabled = 1

    # Format: "username:bcrypt_hash"
    users = [
      "admin:{ADMIN_PASSWORD}"
    ]
  }
  jwt_auth {
    # enable
    enabled = 1
    secret = "{ADMIN_SECRET}"
  }
}


# -------------------------------------------------------------
# STORAGE
# -------------------------------------------------------------
storage {
  # Directory containing .hcl files for individual hosts/domains
  hosts_dir = "{HOST_DIR}"

  # Directory where TLS certificates are stored/cached
  certs_dir = "{CERTS_DIR}"

  # Data directory used for Firewall, etc.
  data_dir = "{DATA_DIR}"
}

# -------------------------------------------------------------
# LOGGING
# -------------------------------------------------------------
logging {
  # enable
  enabled = 1

  # Levels: debug, info, warn, error
  level = "info"

  # Optional JSON log file
  file = "{LOGS_DIR}/agbero.log"

  # Skip Prefix
  skip = [
    "/health",
    "/metrics",
    "/uptime",
    "/logs",
    "/favicon.ico"
  ]

  # VictoriaLogs Integration (Optional)
  # victoria {
  #   enabled    = false
  #   url        = "http://localhost:9428"
  #   batch_size = 500
  # }
}

# -------------------------------------------------------------
# SECURITY
# -------------------------------------------------------------
security {
  # enable
  enabled = 1

  trusted_proxies = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
  ]

  firewall {
    enabled = 1
    mode    = "active"

    inspect_body      = true
    max_inspect_bytes = 8192
    inspect_content_types = ["application/json", "application/x-www-form-urlencoded"]

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

    # --- ACTIONS ---

    action "ban_hard" {
      mitigation = "add"
      response {
        status_code   = 403
        content_type  = "application/json"
        body_template = "{\"error\": \"Permanent Ban\", \"rule\": \"{{.RuleName}}\"}"
      }
    }

    action "ban_short" {
      mitigation = "add"
      response {
        status_code   = 429
        body_template = "Too many requests. Triggered: {{.RuleName}}"
      }
    }

    action "log_only" {
      mitigation = "none"
      logging {
        level = "warn"
      }
    }

    # --- RULES ---

    # 1. Whitelist Internal Tools
    rule "allow_internal_monitoring" {
      priority = 5
      type     = "whitelist"
      match {
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

    # 2. Block Known Bad IPs
    rule "global_blacklist" {
      priority = 10
      type     = "static"
      action   = "ban_hard"
      match {
        ip = ["1.2.3.4", "5.6.7.0/24"]
      }
    }

    # 3. SQL Injection Protection
    rule "block_sqli" {
      priority = 20
      type     = "dynamic"
      action   = "ban_hard"

      match {
        any {
          location = "body"
          pattern  = "(?i)(union\\s+select|select\\s+.*\\s+from)"
        }
        any {
          location = "query"
          pattern  = "(?i)(union\\s+select|select\\s+.*\\s+from)"
        }
      }
    }

    # 4. Login Brute Force Protection
    rule "protect_login" {
      priority = 30
      type     = "dynamic"
      action   = "ban_short"

      match {
        path = ["/login", "/auth"]
        methods = ["POST"]

        threshold {
          count     = 5
          window    = "1m"
          track_by  = "ip"
          on_exceed = "ban"
        }
      }
    }

    # 5. Block Suspicious User Agents
    rule "bad_bots" {
      priority = 40
      type     = "dynamic"
      action   = "ban_hard"

      match {
        any {
          location = "header"
          key      = "User-Agent"
          operator = "contains"
          value    = "sqlmap"
        }
        any {
          location = "header"
          key      = "User-Agent"
          operator = "contains"
          value    = "nikto"
        }
        any {
          location = "header"
          key      = "User-Agent"
          operator = "empty"
        }
      }
    }
  }
}

# -------------------------------------------------------------
# GENERAL TWEAKS
# -------------------------------------------------------------
general {
  # Maximum size of request headers in bytes (Default: 1MB)
  max_header_bytes = 1048576
}

# -------------------------------------------------------------
# ACME / LET'S ENCRYPT
# -------------------------------------------------------------
letsencrypt {
  # enable
  enabled = 1

  # Email used for registration and recovery contact
  email = "admin@example.com"

  # Use staging CA (untrusted) for testing to avoid rate limits
  staging = false

  # Request short-lived certificates (optional)
  short_lived = false
}

# -------------------------------------------------------------
# GLOBAL TIMEOUTS (Optional)
# -------------------------------------------------------------
timeouts {  # enable
  enabled = 1

  read        = "30s"
  write       = "60s"
  idle        = "120s"
  read_header = "5s"
}

# -------------------------------------------------------------
# GLOBAL RATE LIMITING (Optional)
# -------------------------------------------------------------
rate_limits {
  enabled     = 1
  ttl         = "30m"
  max_entries = 100000

  # Black Friday / Payment Rules (Applied First)
  rule "payment" {
    prefixes = ["/api/checkout", "/api/payment"]
    methods = ["POST", "PUT"]
    requests = 5
    window   = "1m"
    key      = "ip" # or "header:Authorization"
  }

  # Auth Rules
  rule "auth_limit" {
    prefixes = ["/login", "/auth", "/admin"]
    requests = 10
    window   = "1m"
    key      = "ip"
  }

  # General API Rules (Matched if above don't apply)
  rule "general_api" {
    prefixes = ["/api"]
    requests = 1000
    window   = "1m"
    key      = "header:X-API-Key"
  }

  # Testing url
  rule "testing" {
    prefixes = ["/testing"]
    requests = 1000000
    window   = "1m"
    key      = "ip"
  }

  # Catch-all
  rule "global" {
    requests = 5000
    window   = "1m"
    key      = "ip"
  }
}

# -------------------------------------------------------------
# CLUSTERING / GOSSIP (Optional)
# -------------------------------------------------------------
gossip {
  enabled = 1
  port    = 7946

  # Secret key for encryption (16, 24, or 32 bytes)
  # secret_key = "..."

  # Initial peers to join
  # seeds = ["10.0.0.2:7946", "10.0.0.3:7946"]

  # Private key for verifying dynamic app registrations
  # private_key_file = "/etc/agbero/cluster.key"
}