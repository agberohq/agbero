domains = ["localhost"]

route "/consul" {
  backends = ["http://localhost:8500"]
  strip_prefixes = ["/consul"]
}