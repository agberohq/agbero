bind {
  http    = [":80", ":8080"]
  https   = [":443"]
  metrics = ":9090"
}

hosts_dir = "./hosts.d"
le_email = "admin@example.com"
trusted_proxies = ["127.0.0.1/32"]
max_header_bytes = 1048576
tls_storage_dir  = "/var/lib/agbero/certmagic"

timeouts {
  read        = "10s"
  write       = "30s"
  idle        = "120s"
  read_header = "5s"
}

rate_limits {
  ttl         = "30m"
  max_entries = 100000
  auth_prefixes = ["/login", "/otp", "/auth"]

  global {
    requests = 120
    window   = "1s"
    burst    = 240
  }

  auth {
    requests = 10
    window   = "1m"
    burst    = 10
  }
}