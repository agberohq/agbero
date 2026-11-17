# =============================================================================
# Vite/React SPA + Node API
# =============================================================================
# The frontend is static; the API is a separate Node service. Keeping /api
# on a backend route means cookies, Authorization headers, and streaming
# responses are forwarded unchanged.

domains     = ["app.example.com"]
compression = true

tls {
  mode = "letsencrypt"
  letsencrypt {
    enabled = "on"
    email   = "ops@example.com"
  }
}

route "/api" {
  enabled  = "on"
  protocol = "http"

  backend {
    strategy = "round_robin"
    server {
      address = "http://127.0.0.1:3001"
    }
  }
}

route "/" {
  enabled  = "on"
  protocol = "http"

  web {
    enabled = "on"
    root    = "/var/www/app/dist"
    index   = ["index.html"]
    listing = "off"
    spa     = "on"
  }
}
