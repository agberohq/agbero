# =============================================================================
# API gateway
# =============================================================================
# JWT validation, rate limiting and CORS at the edge; the upstream receives
# the authenticated user id as a trusted header.

domains = ["api.example.com"]

tls {
  mode = "letsencrypt"
  letsencrypt {
    enabled = "on"
    email   = "ops@example.com"
  }
}

route "/v1" {
  enabled  = "on"
  protocol = "http"

  jwt_auth {
    enabled = "on"
    secret  = "ss://auth/jwt-secret"
    claims_to_headers = {
      "sub" = "X-User-ID"
    }
  }

  rate_limit {
    enabled = "on"
    rule {
      requests = 600
      window   = "1m"
      burst    = 100
      key      = "header:X-User-ID"
    }
  }

  cors {
    enabled         = "on"
    allowed_origins = ["https://app.example.com"]
    allowed_methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]
    allow_credentials = true
  }

  backend {
    strategy = "least_response_time"
    server {
      address = "http://127.0.0.1:8080"
    }
  }
}
