domains = ["example.com"]

web {
  root = "/var/www/html"
}

route "/api/*" {
  backends = ["http://backend:8080"]
  strip_prefixes = ["/api"]
}