domains = ["admin.localhost"]

# Global authentication protection across all routes
# Values: "on" | "off"
protected = "on"

## Admin API/Backend Route Configuration
## This route proxies requests to the admin service running on port 9090
route "/" {
  # Request timeout settings
  timeouts {
    # Maximum time allowed for the entire request to complete
    # Includes proxy forwarding, backend processing, and response delivery
    request = "60s"
  }

  # Health check configuration for monitoring backend service availability
  health_check {
    # Enable active health checking for this route
    # Values: "on" | "off"
    enabled   = "on"

    # Endpoint path on the backend service to check health status
    # Should return 2xx/3xx status codes for healthy state
    path      = "/healthz"

    # Frequency of health check requests
    interval  = "10s"

    # Maximum time to wait for health check response before marking as failed
    timeout   = "5s"

    # Number of consecutive failures required before marking backend as unhealthy
    # Higher values prevent flapping during transient issues
    threshold = 3
  }

  # Backend server configuration
  backend {
    # Single backend server definition
    # For multiple servers, use multiple 'server' blocks with load balancing
    server {
      # Backend service address
      # Formats: "http://host:port", "https://host:port", "unix:/path/to/socket"
      address = "http://127.0.0.1:9090"

      # Streaming response configuration
      streaming {
        # Enable chunked transfer encoding for streaming responses
        # Required for Server-Sent Events (SSE), large file transfers, or real-time data
        # Values: true | false
        enabled = true
      }
    }
  }

  # IP-based access control list (ACL)
  # Restrict this route to specific client IP addresses
  # Useful for admin interfaces that should only be accessible locally
  # Formats: IPv4 addresses (127.0.0.1), IPv6 addresses (::1), CIDR ranges (192.168.1.0/24)
  allowed_ips = ["127.0.0.1", "::1"]
}