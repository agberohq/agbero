# =============================================================================
# Next.js server (SSR + API routes)
# =============================================================================
# Next.js owns the whole path space. Run `next start` on loopback and proxy
# everything to it; do not enable SPA mode here because Next handles routing
# and server-rendered responses itself.

domains     = ["www.example.com"]
compression = true

tls {
  mode = "letsencrypt"
  letsencrypt {
    enabled = "on"
    email   = "ops@example.com"
  }
}

route "/" {
  enabled  = "on"
  protocol = "http"

  timeouts {
    enabled = "on"
    request = "5m"
  }

  backend {
    strategy = "round_robin"
    server {
      address = "http://127.0.0.1:3000"
      streaming {
        enabled        = "on"
        flush_interval = "100ms"
      }
    }
  }
}
