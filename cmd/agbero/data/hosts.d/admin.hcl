domains = ["admin.localhost"]

# The route label must be a PATH (e.g. "/" or "/api"), not a domain.
route "/" {
  backend {
    server {
      address = "http://127.0.0.1:9090"
    }
  }

  # Optional: Restrict access to this specific route
  allowed_ips = ["127.0.0.1", "::1"]
}