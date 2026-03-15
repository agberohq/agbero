domains = ["example.localhost"]

route "/*" {

  # ---------------------------------------------------------
  # RATE LIMIT BYPASS
  # ---------------------------------------------------------
  rate_limit {
    # Tell Agbero to ignore the global rate_limits defined in agbero.hcl
    ignore_global = true


    # Testing url
    rule "testing" {
      prefixes = ["/testing"]
      requests = 1000000
      window   = "1m"
      key      = "ip"
    }

  }

  health_check {
    path = "/health"
  }

  backend {
    server {
      address = "http://localhost:6060"
      weight = 2
    }
    server {
      address = "http://localhost:6061"
      weight = 1
    }
    server {
      address = "http://localhost:6062"
      weight = 1
    }
    server {
      address = "http://localhost:6063"
      weight = 1
    }
    server {
      address = "http://localhost:6064"
      weight = 1
    }
    server {
      address = "http://localhost:6065"
      weight = 1
    }
  }
}