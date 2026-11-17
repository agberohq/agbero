# =============================================================================
# Image service + support site
# =============================================================================
# /api is the weighted image-processing pool. /support is a separate random
# pool. The static frontend is served from /var/www/imigify.
#
# Weighted routing is useful when one image worker has more capacity; random
# is acceptable for the independent support service.

domains = ["imigify.localhost"]

route "/api" {
  backend {
    strategy = "round_robin"

    server {
      address = "http://localhost:6060"
      weight  = 3
    }
    server {
      address = "http://localhost:6061"
      weight  = 1
    }
  }
}

route "/support" {
  backend {
    strategy = "random"
    server {
      address = "http://localhost:7060"
    }
    server {
      address = "http://localhost:7061"
    }
  }
}

route "/" {
  web {
    root    = "/var/www/imigify"
    listing = true
  }
}
