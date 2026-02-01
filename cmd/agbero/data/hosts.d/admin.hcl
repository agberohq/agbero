domains = ["admin.localhost"]


## Default route for the admin
route "/" {
  backend {
    server {
      address = "http://127.0.0.1:9090"
    }
  }

  # Optional: Restrict access to this specific route
  allowed_ips = ["127.0.0.1", "::1"]
}