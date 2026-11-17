# =============================================================================
# Agbero-hosted login for a route
# =============================================================================
# Use this when the upstream has no login of its own, for example the
# CockroachDB Admin UI. The browser signs in at:
#
#   /admin/_agbero/login
#
# and receives an HttpOnly, route-scoped session cookie. The password is never
# sent to the backend and the bcrypt hash never leaves Agbero/Keeper.
#
# Basic Auth remains available for scripts and low-risk routes. Do not enable
# both basic_auth and protect on the same route.

domains = ["cockroach.example.com"]

tls {
  mode = "letsencrypt"
  letsencrypt {
    enabled = "on"
    email   = "ops@example.com"
  }
}

route "/admin" {
  enabled  = "on"
  protocol = "http"

  protect {
    enabled     = "on"
    title       = "Cockroach Admin"
    users       = [
      # Generate with: agbero secret hash --password '...'
      # and store the hash in Keeper under auth/users/cockroach/alice.
      "alice:ss://auth/users/cockroach/alice",
      "bob:ss://auth/users/cockroach/bob",
    ]
    session_ttl = "8h"
  }

  # The login/logout endpoints are derived below the route:
  #   /admin/_agbero/login
  #   /admin/_agbero/logout
  #
  # A reverse proxy or CDN should not cache these endpoints.

  backend {
    server {
      address = "http://127.0.0.1:8080"
    }
  }
}
