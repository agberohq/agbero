# =============================================================================
# Weighted canary deployment
# =============================================================================
# Start with a small weight on the canary. Health checks remove an unhealthy
# target automatically; circuit breakers prevent a failing canary from
# consuming all traffic.

domains = ["app.example.com"]

route "/" {
  enabled  = "on"
  protocol = "http"

  backend {
    strategy = "weighted_least_conn"

    server {
      address = "http://127.0.0.1:8080"
      weight  = 95
    }

    server {
      address = "http://127.0.0.1:8081"
      weight  = 5
    }
  }

  health_check {
    enabled  = "on"
    path     = "/healthz"
    interval = "5s"
    timeout  = "2s"
  }

  circuit_breaker {
    enabled   = "on"
    threshold = 5
    duration  = "30s"
  }
}
