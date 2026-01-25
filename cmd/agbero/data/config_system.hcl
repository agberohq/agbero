# Agbero Configuration (System/Production)
development = false

bind {
  http = [":80"]
  https = [":443"]
  metrics = "127.0.0.1:9090" # Secure metrics by default
}

storage {
  # Hosts directory injected by Agbero install
  hosts_dir = "%s"
  certs_dir = "./certs.d"
}

logging {
  level = "info"
  # file = "/var/log/agbero/agbero.log" # Uncomment to enable file logging
}

general {
  max_header_bytes = 1048576 # 1MB
}

security {
  # Configure your load balancer IPs here if behind one (e.g., AWS ALB, Cloudflare)
  # trusted_proxies = ["10.0.0.0/8"]
}

letsencrypt {
  # Email is required for production certificates
  # email = "admin@example.com"
  staging = false
}
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