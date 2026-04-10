# RSS Proxy Replay Configuration
# Replaces the Go-based RSS proxy server with declarative HCL

domains = ["cors.localhost"]

route "/*" {
  serverless {
    enabled = true

    replay "rss_proxy" {
      name    = "rss_proxy"
      enabled = true

      # === Mode Configuration ===
      # Empty URL enables replay mode (dynamic upstream from request)
      url = ""

      # === Security & Domain Allowlist ===
      # Restrict proxy targets to prevent SSRF
      allowed_domains = [
        "*.rss.example.com",
        "feeds.example.org",
        "*.news-api.com"
        # "*" # Uncomment only for unrestricted testing
      ]

      # === Request Handling ===
      methods = ["GET"]  # RSS feeds are GET-only

      # Browser-like headers for feed compatibility
      headers = {
        "User-Agent"      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        "Accept"          = "application/rss+xml, application/xml, text/xml, */*"
        "Accept-Language" = "en-US,en;q=0.9"
      }

      # Forward incoming query params (enables ?url= parameter)
      forward_query = true

      # === Referer Handling ===
      # Auto-derive Referer from target URL (matches Go proxy behavior)
      referer_mode = "auto"

      # === Response Processing ===
      # Strip upstream CORS/security headers that conflict with proxy responses
      strip_headers = true

      # === Performance ===
      timeout = "20s"

      # === Optional Endpoint Authentication ===
      # auth {
      #   enabled = false
      #   method = "token"  # meta | token | direct
      #   secret  = "${env.REPLAY_SECRET}"
      # }

      # === Caching ===
      # Mirrors Go proxy TTL logic: short for feeds, longer for media
      cache {
        enabled = true
        ttl     = "2m"  # Default fallback

        # Resource limits (match Go mappo.Cache)
        max_items = 10000
      }
    }

  }
}


