# =============================================================================
# Server-Sent Events (SSE)
# =============================================================================
# SSE is a long-lived HTTP response. Disable compression for the route and
# give it a long request timeout; the proxy flushes events instead of
# buffering the whole response.

domains     = ["events.example.com"]
compression = false

tls {
  mode = "letsencrypt"
  letsencrypt {
    enabled = "on"
    email   = "ops@example.com"
  }
}

route "/events" {
  enabled  = "on"
  protocol = "http"

  timeouts {
    enabled = "on"
    request = "24h"
  }

  backend {
    server {
      address = "http://127.0.0.1:8091"
      streaming {
        enabled        = "on"
        flush_interval = "250ms"
      }
    }
  }
}
