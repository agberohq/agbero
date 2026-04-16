# RSS Proxy — relay mode: client passes ?url= and agbero forwards it
domains = ["cors.localhost"]

route "/*" {
  serverless {
    enabled = true

    replay "rss" {
      # Name comes from the label above ("rss") — endpoint is reachable at /rss
      # URL is empty = relay mode: target URL comes from X-Agbero-Replay-Url header
      # or ?url= query parameter
      enabled = true
      url     = ""

      # Security: only allow these outbound domains (prevents SSRF)
      # WARNING: "*" allows all external domains — use only for development
      allowed_domains = ["*"]

      # Only accept GET requests — RSS feeds don't need POST
      methods = ["GET"]

      # Forward the ?url= query param to... actually in relay mode the url
      # param is consumed by agbero to determine the target — not forwarded
      # forward_query only forwards OTHER query params to the upstream
      forward_query = false

      # Browser-like headers so feed servers don't reject the request
      headers = {
        "User-Agent"      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        "Accept"          = "application/rss+xml, application/xml, text/xml, */*"
        "Accept-Language" = "en-US,en;q=0.9"
      }

      # Set Referer to the target's own origin (mimics browser behaviour)
      referer_mode = "auto"

      # Strip upstream CORS/security headers — agbero will re-add CORS
      strip_headers = true

      timeout = "20s"

      cache {
        enabled = true
        driver  = "memory"
        ttl     = "2m"
        methods = ["GET"]

        memory {
          max_items = 10000   # must be inside memory block, not at cache level
        }
      }
    }
  }
}