# =============================================================================
# WebSocket application
# =============================================================================
# A dedicated path keeps the upgrade isolated from normal HTTP routes.
# WebSocket connections require HTTP/1.1 at the client; most browsers handle
# this automatically. Enable streaming so the upgraded connection is not
# buffered by the proxy.

domains     = ["chat.example.com"]
compression = false

tls {
  mode = "letsencrypt"
  letsencrypt {
    enabled = "on"
    email   = "ops@example.com"
  }
}

route "/ws" {
  enabled  = "on"
  protocol = "http"

  timeouts {
    enabled = "on"
    request = "24h"
  }

  backend {
    server {
      address = "http://127.0.0.1:8081"
      streaming {
        enabled        = "on"
        flush_interval = "0s"
      }
    }
  }
}

# Optional static client shell
route "/" {
  enabled = "on"
  web {
    enabled = "on"
    root    = "/var/www/chat"
    spa     = "on"
    listing = "off"
  }
}
