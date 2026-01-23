# This file handles the specific subdomain
domains = ["example.localhost"]

route "/example*" {
  backends = ["http://localhost:6060"]
  strip_prefixes = ["/example"]
}