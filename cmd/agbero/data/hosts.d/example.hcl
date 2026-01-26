domains = ["example.localhost"]

route "/*" {
  backend {
    server {
      address = "http://localhost:6060"
      weight = 2
    }
    server {
      address = "http://localhost:6061"
      weight = 1
    }
    server {
      address = "http://localhost:6062"
      weight = 1
    }
    server {
      address = "http://localhost:6063"
      weight = 1
    }
    server {
      address = "http://localhost:6064"
      weight = 1
    }
    server {
      address = "http://localhost:6065"
      weight = 1
    }
  }
}