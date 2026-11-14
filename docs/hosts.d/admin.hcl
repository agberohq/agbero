# =============================================================================
# Admin / dashboard host
# =============================================================================
# Proxies the local Agbero admin listener. Keep this host on a private
# interface or restrict it with allowed_ips; the admin API is not a public
# website.
#
# The request timeout is intentionally longer than a normal page request
# because /logs and /uptime can take a moment to gather data.

domains = ["admin.localhost"]


## Default route for the admin
route "/" {
  timeouts {
    request = "60s"
  }
  backend {
    server {
      address = "http://127.0.0.1:9090"
      streaming {
        enabled = true
      }
    }
  }

  # Optional: Restrict access to this specific route
  allowed_ips = ["127.0.0.1", "::1"]
}