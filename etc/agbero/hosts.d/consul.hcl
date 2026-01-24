# This file handles the specific subdomain
domains = ["consul.localhost"]

# Since it's a dedicated domain, we map root directly.
# No strip_prefixes needed.
route "/*" {
  backends = ["http://localhost:8500"]
}