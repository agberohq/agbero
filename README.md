# agbero - Production Reverse Proxy

A minimal, production-grade reverse proxy with Let's Encrypt 2026 support.

## Features
- Simple HCL configuration
- Automatic Let's Encrypt TLS (6-day certs ready)
- Static file serving (`web` block)
- Path-based routing with prefix stripping
- Multiple load balancing strategies

## Quick Start

### Install:

```bash
go install git.imaxinacion.net/aibox/agbero@latest
```


```hcl
server_names = ["static.example.com"]

web {
  root = "/var/www/static"
  index = "index.html"
}
```


```hcl
server_names = ["api.example.com"]

route "/v1/*" {
  backends = ["http://api-1:8080", "http://api-2:8080"]
  strip_prefixes = ["/v1"]
  lb_strategy = "leastconn"
}
```


```hcl
server_names = ["localhost"]

web {
  root = "./public"
}

letsencrypt {
  staging = true
}
```


```
# API Gateway
server_names = ["api.example.com"]

route "/users/*" {
  backends = [
    "http://user-service-1:8080",
    "http://user-service-2:8080"
  ]
  strip_prefixes = ["/users"]
  lb_strategy = "roundrobin"
}

route "/orders/*" {
  backends = ["http://order-service:8081"]
  strip_prefixes = ["/orders"]
}
```


