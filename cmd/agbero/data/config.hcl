bind {
  http    = [":80"]
  https   = [":443"]
  metrics = ":9090"
}

hosts_dir = "%s"
le_email = "admin@example.com"
development = true

# trusted_proxies = ["127.0.0.1/32"]

timeouts {
  read  = "10s"
  write = "30s"
}

rate_limits {
  global {
    requests = 120
    window   = "1s"
  }
  auth {
    requests = 10
    window   = "1m"
  }
}