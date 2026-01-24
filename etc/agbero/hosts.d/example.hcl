# This file handles the specific subdomain
domains = ["example.localhost"]

tls {
  mode = "auto"  # Automatically generate and trust certificates
}

route "/example*" {
  backends = ["http://localhost:6060"]
  strip_prefixes = ["/example"]
}