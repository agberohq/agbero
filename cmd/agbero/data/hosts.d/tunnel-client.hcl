# tunnel client example
domains = ["blog.localhost"]

# The route label must be a PATH (e.g. "/" or "/api"), not a domain.
route "/" {
  backend {
    server {
      address = "http://localhost:3000"
    }
  }
  # Optional: Restrict access to this specific route
  allowed_ips = ["127.0.0.1", "::1"]

  tunnel {
      client {
        domain = "blog.tunnel.agbero.com" ## in case we have multiple domain alisas above
        server = "wss://tunnel.agbero.com/_connect"

        # Auth (standard HTTP headers)
        headers = {
          "Authorization" : "Basic ZGV2OnNlY3JldC1wYXNzd29yZA=="
        }
      }
  }
}