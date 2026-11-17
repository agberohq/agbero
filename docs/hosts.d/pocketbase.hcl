# =============================================================================
# PocketBase behind Agbero
# =============================================================================
#
# Topology:
#
#   browser ──HTTPS──> Agbero (web.example.com)
#                         ├── /        static SPA in /var/www/wo
#                         ├── /api     PocketBase REST, files, realtime SSE
#                         └── /_      PocketBase admin UI
#
# PocketBase runs on loopback:
#
#   ./pocketbase serve --http=127.0.0.1:8090
#
# This is a reverse-proxy route, NOT a replay route. Replay is for outbound
# calls to third-party APIs with server-side credential injection; PocketBase
# is your application backend and must receive the original paths, cookies,
# auth headers, file downloads, and realtime stream.
# =============================================================================

protected    = "off"
domains      = ["web.example.com"]
compression  = false

# PocketBase realtime is SSE. Avoid host-level compression buffering and give
# the API route a long request timeout so the SSE connection is not cut off by
# the global read timeout.
tls {
  mode = "letsencrypt"

  letsencrypt {
    enabled     = "on"
    email       = "ops@example.com"
    staging     = "off"
    short_lived = false
  }
}

# -----------------------------------------------------------------------------
# PocketBase API
# -----------------------------------------------------------------------------
# Covers:
#   /api/collections/...
#   /api/realtime             (SSE)
#   /api/files/...
#   /api/health
#   /api/settings
#
# Do not strip "/api": PocketBase expects its complete route.
route "/api" {
  enabled  = "on"
  protocol = "http"

  timeouts {
    enabled = "on"
    request = "24h"          # realtime SSE can stay open for hours
  }

  backend {
    strategy = "round_robin"

    server {
      address = "http://127.0.0.1:8090"

      streaming {
        enabled        = "on"
        flush_interval = "100ms"
      }
    }
  }
}

# -----------------------------------------------------------------------------
# PocketBase admin UI
# -----------------------------------------------------------------------------
# PocketBase serves its admin dashboard at /_/ . This must be proxied too,
# otherwise the admin UI falls through to the SPA and returns index.html.
# If the admin UI should not be public, protect this route with allowed_ips
# or a firewall rule instead of exposing it to the internet.
route "/_" {
  enabled  = "on"
  protocol = "http"

  backend {
    server {
      address = "http://127.0.0.1:8090"
    }
  }
}

# -----------------------------------------------------------------------------
# Frontend SPA
# -----------------------------------------------------------------------------
# The built frontend lives outside PocketBase. SPA mode makes client-side
# routes such as /artists/42 fall back to index.html while still allowing
# /api and /_ to be handled by the more specific routes above.
route "/" {
  enabled  = "on"
  protocol = "http"

  web {
    enabled = "on"
    root    = "/var/www/wo"
    index   = ["index.html", "index.htm", "index.md", "README.md"]
    listing = "off"
    spa     = "on"

    # Keep files immutable only if your frontend filenames are fingerprinted.
    # cache_control = "public, max-age=31536000, immutable"
  }
}
