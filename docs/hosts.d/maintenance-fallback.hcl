# =============================================================================
# Maintenance page and graceful backend fallback
# =============================================================================
# The fallback is used when all backends are unavailable. For a static
# maintenance page use type = "static"; the response is cacheable for a short
# period so crawlers and clients do not hammer a failing service.

domains = ["app.example.com"]

route "/" {
  enabled  = "on"
  protocol = "http"

  fallback {
    enabled      = "on"
    type         = "static"
    status_code  = 503
    content_type = "text/html"
    body         = "<!doctype html><title>Maintenance</title><h1>We are performing maintenance</h1>"
    cache_ttl    = 30
  }

  backend {
    strategy = "round_robin"
    server {
      address = "http://127.0.0.1:8080"
    }
  }

  health_check {
    enabled  = "on"
    path     = "/healthz"
    interval = "5s"
  }
}
