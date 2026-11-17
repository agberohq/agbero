# =============================================================================
# Consul HTTP UI / API
# =============================================================================
# Simple reverse proxy to the local Consul agent. Consul's UI uses its own
# cookies and API prefix, so preserve the full path (no strip_prefixes).

domains = ["consul.localhost"]

route "/*" {
  backend {
    server {
      address = "http://localhost:8500"
    }
  }
}