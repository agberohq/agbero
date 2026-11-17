# =============================================================================
# CockroachDB: TCP proxy plus optional admin UI
# =============================================================================
# The SQL listener is raw TCP, not HTTP. The optional route below proxies the
# CockroachDB Admin UI and uses ip_hash so the browser stays on one node.
#
# Backends use the tcp:// scheme so the intent is explicit. Agbero will still
# dial the host:port, but the scheme documents the transport.

domains = ["cockroach.localhost"]

# -----------------------------------------------------------------------
# TCP Proxy Configuration for CockroachDB (SQL Interface)
# -----------------------------------------------------------------------
proxy "primary" {
  # The port Agbero will listen on (Standard CockroachDB port)
  # This works regardless of the 'domains' above because it binds
  # explicitly to port 4045 on the host machine.
  listen = ":4045"

  # Strategy: "least_conn" is highly recommended for Databases.
  # It ensures new connections go to the node with the fewest active links,
  # balancing the load perfectly when connections are long-lived.
  strategy = "least_conn"

  # Node 1
  backend {
    address = "tcp://127.0.0.1:26257"
    weight  = 10
  }

  # Node 2
  backend {
    address = "tcp://127.0.0.1:26258"
    weight  = 10
  }

  # Node 3
  # this an intentional bad node
  backend {
    address = "tcp://127.0.0.1:26259"
    weight  = 10
  }
}

# -----------------------------------------------------------------------
# Optional: HTTP Reverse Proxy for CockroachDB Admin UI
# -----------------------------------------------------------------------
route "/*" {
  backend {

    server {
      address = "http://127.0.0.1:7580"
    }

    server {
      address = "http://127.0.0.1:7581"
    }
    # Use "ip_hash" for UI to keep session stickiness
    strategy = "ip_hash"
  }
}