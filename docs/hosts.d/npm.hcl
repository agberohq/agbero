# =============================================================================
# Local Vite/npm development server
# =============================================================================
# Vite binds to 5173 and owns its own static assets and HMR endpoint. Proxy the
# whole path space; do not add SPA fallback here because Vite already handles
# client-side routes in development.

domains = ["npm.localhost"]

route "/*" {
  backend {
    server {
      address = "http://localhost:5173"
      weight  = 2
    }
  }
}