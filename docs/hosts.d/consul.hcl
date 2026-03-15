domains = ["consul.localhost"]

route "/*" {
  backend {
    server {
      address = "http://localhost:8500"
    }
  }
}