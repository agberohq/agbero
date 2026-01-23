domains = ["localhost"]

route "/consul*" {
  backends = ["http://localhost:8500/"]
  strip_prefixes = ["/consul"]
}


route "/example*" {
  backends = ["http://localhost:6060"]
  strip_prefixes = ["/example"]
}
