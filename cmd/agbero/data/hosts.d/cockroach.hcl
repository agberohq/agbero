# The 'domains' field is required by the schema, but ignored for pure TCP proxies.
domains = ["cockroach.internal"]

# -----------------------------------------------------------------------
# TCP Proxy Configuration for CockroachDB (SQL Interface)
# -----------------------------------------------------------------------
tcp_proxy {
  # The port Agbero will listen on (Standard CockroachDB port)
  listen = ":26257"

  # Strategy: "least_conn" is highly recommended for Databases.
  # It ensures new connections go to the node with the fewest active links,
  # balancing the load perfectly when connections are long-lived.
  strategy = "least_conn"

  # Node 1
  backend {
    address = "192.168.1.101:26257"
    weight  = 10
  }

  # Node 2
  backend {
    address = "192.168.1.102:26257"
    weight  = 10
  }

  # Node 3
  backend {
    address = "192.168.1.103:26257"
    weight  = 10
  }
}

# -----------------------------------------------------------------------
# Optional: HTTP Reverse Proxy for CockroachDB Admin UI
# -----------------------------------------------------------------------
route "/admin" {
  strip_prefixes = ["/admin"]

  backend {
    server {
      address = "http://192.168.1.101:8080"
    }
    server {
      address = "http://192.168.1.102:8080"
    }
    server {
      address = "http://192.168.1.103:8080"
    }

    # Use "ip_hash" for UI to keep session stickiness
    lb_strategy = "ip_hash"
  }
}