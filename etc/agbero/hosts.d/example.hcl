domains = ["example.localhost"]

route "/example*" {
  strip_prefixes = ["/example"]
  backend {
    server {
      address = "http://localhost:6060"
    }
  }
}