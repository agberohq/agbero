domains = ["admin.localhost"]

## Default route for the admin
route "/" {
  timeouts {
    request = "60s"
  }
  backend {
    server {
      address = "http://127.0.0.1:9090"
      streaming {
        enabled = true
      }
    }
  }

  # Optional: Restrict access to this specific route
  allowed_ips = ["127.0.0.1", "::1"]
}