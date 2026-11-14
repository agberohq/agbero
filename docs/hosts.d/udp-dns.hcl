# =============================================================================
# UDP DNS load balancer
# =============================================================================
# protocol = "udp" selects the datagram proxy. matcher = "dns" keeps a flow
# pinned to the same resolver; allowed DNS blocking is configured separately.

domains = ["dns.localhost"]

# Host validation requires at least one route even when the public traffic is
# pure UDP. This optional HTTP route can expose DNS health/metrics; remove it
# if your Agbero version permits proxy-only hosts.
route "/healthz" {
  enabled  = "on"
  protocol = "http"
  backend {
    server { address = "http://127.0.0.1:8080" }
  }
}

proxy "dns" {
  enabled     = "on"
  listen      = ":5353"
  protocol    = "udp"
  matcher     = "dns"
  strategy    = "round_robin"
  session_ttl = "30s"

  backend {
    address = "udp://1.1.1.1:53"
  }

  backend {
    address = "udp://8.8.8.8:53"
  }
}
