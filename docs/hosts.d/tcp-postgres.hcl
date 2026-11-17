# =============================================================================
# TCP load balancer for PostgreSQL
# =============================================================================
# This is a raw TCP proxy, not an HTTP route. Use least_conn because database
# connections are long-lived; the backend addresses use the tcp:// scheme.

domains = ["db.localhost"]

# Host validation requires at least one route even when the public traffic is
# pure TCP. This optional loopback-only HTTP route can expose a small admin or
# health endpoint; remove it if your Agbero version permits proxy-only hosts.
route "/healthz" {
  enabled  = "on"
  protocol = "http"
  backend {
    server { address = "http://127.0.0.1:8080" }
  }
}

proxy "postgres" {
  enabled  = "on"
  listen   = ":5432"
  strategy = "least_conn"

  backend {
    address = "tcp://127.0.0.1:5432"
  }

  backend {
    address = "tcp://127.0.0.1:5433"
  }

  health_check {
    enabled  = "on"
    interval = "10s"
    timeout  = "2s"
  }
}
