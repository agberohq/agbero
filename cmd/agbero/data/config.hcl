# Agbero Full Configuration Reference

# -------------------------------------------------------------
# GLOBAL SETTINGS
# -------------------------------------------------------------

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

  # Address for Prometheus metrics and health check
  metrics = ":9090"
}

# -------------------------------------------------------------
# STORAGE
# -------------------------------------------------------------
storage {
  # Directory containing .hcl files for individual hosts/domains
  hosts_dir = "{HOST_DIR}"

  # Directory where TLS certificates are stored/cached
  certs_dir = "./certs.d"
}

# -------------------------------------------------------------
# LOGGING
# -------------------------------------------------------------
logging {
  # Levels: debug, info, warn, error
  level = "info"

  # Optional JSON log file
  # file = "/var/log/agbero.log"

  # VictoriaLogs Integration (Optional)
  victoria {
    enabled    = false
    url        = "http://victoria-logs:9428/insert/jsonline"
    batch_size = 500
  }
}

# -------------------------------------------------------------
# SECURITY
# -------------------------------------------------------------
security {
  # List of IP CIDRs to trust for X-Forwarded-For headers.
  # Essential if running behind Cloudflare, AWS ALB, or Nginx.
  trusted_proxies = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
  ]
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
timeouts {
  read        = "10s"
  write       = "30s"
  idle        = "120s"
  read_header = "5s"
}

# -------------------------------------------------------------
# GLOBAL RATE LIMITING (Optional)
# -------------------------------------------------------------
rate_limits {
  ttl = "30m"
  max_entries = 100000

  # Paths that trigger stricter 'auth' rate limits
  auth_prefixes = ["/login", "/auth", "/admin"]

  # General traffic limits
  global {
    requests = 120
    window   = "1s"
    burst    = 240
  }

  # Auth traffic limits
  auth {
    requests = 10
    window   = "1m"
    burst    = 10
  }
}

# -------------------------------------------------------------
# CLUSTERING / GOSSIP (Optional)
# -------------------------------------------------------------
gossip {
  enabled = false
  port    = 7946

  # Secret key for encryption (16, 24, or 32 bytes)
  # secret_key = "..."

  # Initial peers to join
  # seeds = ["10.0.0.2:7946", "10.0.0.3:7946"]

  # Private key for verifying dynamic app registrations
  # private_key_file = "/etc/agbero/cluster.key"
}