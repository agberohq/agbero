# Agbero Advanced Guide

This guide covers advanced features for production deployments at scale: clustering, distributed state, custom health scoring, WebAssembly plugins, and performance optimization.

## Prerequisites

Before diving into advanced features, you should be comfortable with:
- Basic Agbero configuration (`global.md`, `host.md`)
- Command-line usage (`command.md`)
- Linux/Unix system administration
- Networking concepts (TCP/IP, DNS, load balancing)

---

## 1. Clustering & Gossip Protocol

Agbero uses a hybrid clustering approach for multi-node deployments. This enables configuration synchronization, certificate sharing, and distributed rate limiting without external dependencies.

### Architecture Overview

```
┌─────────────────┐     UDP Gossip     ┌─────────────────┐
│   Node 1        │ ◄─────────────────► │   Node 2        │
│                 │     (membership,    │                 │
│                 │      status, locks) │                 │
└────────┬────────┘                     └────────┬────────┘
│                                        │
│ TCP Stream (configs, certs)            │ TCP Stream
▼                                        ▼
┌─────────────────┐     TCP Stream     ┌─────────────────┐
│   Node 3        │ ◄─────────────────► │   Node 4        │
│                 │                     │                 │
└─────────────────┘                     └─────────────────┘
```

- **UDP Gossip**: Node discovery, health status, distributed locks, ACME challenges
- **TCP Streams**: Reliable transfer of host configurations and TLS certificates

### Configuration

```hcl
# agbero.hcl
gossip {
  enabled = true
  port    = 7946  # UDP and TCP port for cluster communication
  
  # Secret key for encryption (16, 24, or 32 bytes after decoding)
  # Generate with: agbero secret cluster
  secret_key = "b64.xVZ9k2mN8pQrS4tU6vW8xY0zA1bC3dE5fG7hI9jK="
  
  # Initial seed nodes to join
  seeds = [
    "10.0.0.2:7946",
    "10.0.0.3:7946",
    "cluster.example.com:7946"
  ]
  
  # Time-to-live for route entries (seconds)
  ttl = 30
}
```

### Cluster Secret Generation

```bash
# Generate a cryptographically secure 32-byte key
agbero secret cluster

# Output:
# Generated 32-byte Secret Key (AES-256 compatible):
# ==================================================
# b64.xVZ9k2mN8pQrS4tU6vW8xY0zA1bC3dE5fG7hI9jK=
# ==================================================
```

### Starting a Cluster

**Seed Node (first node):**
```bash
agbero cluster start --config ./seed.hcl
```

**Joining Node:**
```bash
agbero cluster join 10.0.0.2:7946 --secret b64.xVZ9k2mN8pQrS4tU6vW8xY0zA1bC3dE5fG7hI9jK=
```

### What Gets Synchronized

| Type | Protocol | Description |
|------|----------|-------------|
| Host Configs | TCP | Route definitions synced to `hosts.d/` |
| Certificates | TCP | TLS certificates (private keys encrypted) |
| ACME Challenges | UDP | Let's Encrypt HTTP-01 tokens |
| Node Status | UDP | Health, load, draining state |
| Distributed Locks | UDP | Coordination primitives |

### Cluster Monitoring

```bash
# Check cluster members
curl http://localhost:9090/uptime | jq '.cluster'

# Output:
{
  "enabled": true,
  "members": ["node1", "node2", "node3"],
  "metrics": {
    "updates_received": 1542,
    "updates_ignored": 89,
    "joins": 3,
    "leaves": 1
  }
}
```

---

## 2. Distributed State (Redis Backend)

For rate limiting and firewall counters that need to be consistent across all cluster nodes, Agbero supports Redis as a distributed state backend.

### Configuration

```hcl
# agbero.hcl
gossip {
  enabled = true
  
  shared_state {
    enabled = true
    driver  = "redis"  # "memory" (default) or "redis"
    
    redis {
      host       = "redis.internal"
      port       = 6379
      password   = "${env.REDIS_PASS}"
      db         = 0
      key_prefix = "agbero:state:"
    }
  }
}
```

### How It Works

- **Rate Limit Counters**: Stored in Redis with atomic operations
- **Firewall Thresholds**: Distributed sliding windows
- **Automatic Fail-open**: If Redis is unavailable, falls back to local memory

### What Gets Stored in Redis

```
agbero:state:rl:api:192.168.1.100     # Rate limit counters
agbero:state:fw:block:1.2.3.4         # Firewall bans
agbero:state:fw:threshold:rule:ip     # Threshold counters
```

All Redis interactions are handled internally by Agbero - no Lua scripts or manual Redis configuration needed.

---

## 3. Gradient Health Scoring

Unlike simple up/down checks, Agbero uses a sophisticated 0-100 health score with four states. This enables intelligent traffic shaping and gradual degradation.

### Health States

| State | Score Range | Traffic Weight | Behavior |
|-------|-------------|----------------|----------|
| **Healthy** | 100-80 | 100% | Full production traffic |
| **Degraded** | 79-50 | 50% | Reduced weight, increased probing |
| **Unhealthy** | 49-10 | 10% | Minimal traffic, aggressive probing |
| **Dead** | 9-0 | 0% | No traffic, circuit broken |

### Scoring Factors

```
Final Score = (Latency × 0.40) + (Success Rate × 0.30) + 
              (Passive Errors × 0.20) + (Connection Health × 0.10)
```

### Advanced Configuration

```hcl
# hosts.d/api.hcl
route "/api" {
  backend {
    server { address = "http://app:8080" }
  }

  health_check {
    enabled = true
    path    = "/health"
    
    # Custom latency thresholds
    latency_baseline_ms     = 50      # 50ms = 100% healthy
    latency_degraded_factor = 2.5     # 125ms starts degrading
    unhealthy_ms           = 1000     # 1s = unhealthy
    
    # Probe behavior
    accelerated_probing = true   # Probe faster when unhealthy
    synthetic_when_idle = true    # Probe even with no traffic
    
    # Advanced checks
    method = "GET"
    headers = {
      "X-Health-Check" = "true"
      "User-Agent"     = "Agbero/1.0"
    }
    expected_status = [200, 204]
    expected_body   = "OK"
  }
}
```

### Circuit Breaker Integration

```hcl
circuit_breaker {
  enabled   = true
  threshold = 5    # Failures before opening circuit
  duration  = "30s" # Time in open state
  
  # Health score below 20 automatically opens circuit
}
```

### Monitoring Health Scores

```bash
# View detailed health metrics
curl http://localhost:9090/uptime | jq '.hosts["api.example.com"].routes[0].backends'

# Output:
{
  "url": "http://app:8080",
  "alive": true,
  "in_flight": 3,
  "failures": 0,
  "total_reqs": 15420,
  "latency_us": {
    "p50": 45200,
    "p90": 89300,
    "p99": 145000,
    "avg": 48700
  },
  "health": {
    "status": "Healthy",
    "score": 94,
    "trend": 1,
    "last_check": "2024-01-15T10:30:00Z",
    "last_success": "2024-01-15T10:30:00Z",
    "consecutive_failures": 0
  }
}
```

---

## 4. Advanced Firewall Rules

### Complex Match Conditions

```hcl
security {
  firewall {
    enabled = true
    mode    = "active"  # active, verbose, monitor
    
    # Custom actions
    action "block_country" {
      mitigation = "add"
      response {
        status_code = 403
        body_template = "{\"error\": \"Access denied from your region\"}"
        headers = {
          "X-Block-Reason" = "geo-restriction"
        }
      }
    }
    
    # Complex rule with multiple conditions
    rule "block_suspicious" {
      name        = "block_suspicious"
      description = "Block requests matching multiple suspicious patterns"
      priority    = 100
      type        = "dynamic"
      action      = "block_country"
      duration    = "24h"
      
      match {
        # IP conditions
        ip = ["1.2.3.0/24", "5.6.7.8"]
        
        # Path patterns
        path = ["/wp-admin", "/xmlrpc.php", "/.env"]
        
        # HTTP methods
        methods = ["POST", "PUT"]
        
        # Complex conditions with ANY/ALL/NONE
        any {
          location = "header"
          key      = "User-Agent"
          pattern  = "(?i)(bot|crawler|scanner)"
        }
        
        all {
          location = "header"
          key      = "Accept-Language"
          pattern  = "^(?!en).*"  # Not English
        }
        
        none {
          location = "header"
          key      = "X-API-Key"
          operator = "missing"
        }
        
        # Extract values for threshold tracking
        extract {
          enabled = true
          from    = "query"
          pattern = "token=([a-f0-9]{32})"
          as      = "api_token"
        }
        
        # Threshold-based blocking
        threshold {
          enabled    = true
          count      = 100
          window     = "1m"
          track_by   = "ip"
          group_by   = "extracted.api_token"
          on_exceed  = "rate_limit"
        }
      }
    }
  }
}
```

### Match Condition Reference

| Location | Description | Example |
|----------|-------------|---------|
| `ip` | Client IP address | `"10.0.0.0/8"` |
| `path` | URL path | `"/admin"` |
| `method` | HTTP method | `"POST"` |
| `header` | HTTP header | `key = "User-Agent"` |
| `query` | Query parameter | `key = "token"` |
| `body` | Request body | `pattern = "password="` |
| `uri` | Full URI | `pattern = "\.php$"` |

### Operators

| Operator | Description | Example |
|----------|-------------|---------|
| (none) | Exact match | `value = "admin"` |
| `contains` | Contains substring | `operator = "contains"` |
| `prefix` | Starts with | `operator = "prefix"` |
| `suffix` | Ends with | `operator = "suffix"` |
| `pattern` | Regex match | `pattern = "^\\d+$"` |
| `empty` | Value is empty | `operator = "empty"` |
| `missing` | Key doesn't exist | `operator = "missing"` |

---

## 5. Advanced TLS & mTLS

### Client Certificate Authentication (mTLS)

```hcl
# hosts.d/internal.hcl
domains = ["secure.internal"]

tls {
  mode = "local"
  local {
    cert_file = "/etc/certs/server.crt"
    key_file  = "/etc/certs/server.key"
  }
  
  # Require client certificates
  client_auth = "require_and_verify"  # none, request, require, require_and_verify, verify_if_given
  
  # Trusted client CAs
  client_cas = [
    "/etc/ca/client-ca-1.crt",
    "/etc/ca/client-ca-2.crt"
  ]
}

route "/" {
  backend {
    server { address = "https://internal-app:8443" }
  }
}
```

### Certificate Management Automation

Agbero automatically manages certificate lifecycle:

```hcl
letsencrypt {
  enabled = true
  email   = "admin@example.com"
  
  # Staging for testing (untrusted certs)
  staging = false
  
  # Short-lived certificates (1-7 days)
  short_lived = true
  
  # Custom ACME directory (for private CA)
  # pebble {
  #   enabled = true
  #   url     = "https://localhost:14000/dir"
  #   insecure = true
  # }
}
```

### Certificate Storage

Certificates are stored encrypted in `certs.d/`:

```
certs.d/
├── acme_account.key          # Encrypted ACME account key
├── example.com.crt           # Certificate
├── example.com.key.enc       # Encrypted private key
├── api.example.com.crt
├── api.example.com.key.enc
└── ca-cert.pem               # Local CA (development)
```

---

## 6. Performance Tuning

### System Limits

```hcl
# agbero.hcl
general {
  max_header_bytes = 2097152  # 2MB headers
}

timeouts {
  enabled     = true
  read        = "60s"
  write       = "60s"
  idle        = "300s"  # Longer keep-alive for many connections
  read_header = "10s"
}
```

### Connection Pooling

```hcl
backend {
  server {
    address = "http://app:8080"
    max_connections = 10000  # Per-backend connection limit
    
    streaming {
      enabled        = true
      flush_interval = "100ms"  # For WebSocket/SSE
    }
  }
}
```

### Cache Tuning

```hcl
cache {
  enabled = true
  driver  = "memory"
  ttl     = "1h"
  
  memory {
    max_items = 100000  # Route cache size
  }
}

# TCP proxy cache
gossip {
  ttl = 30  # Route entry TTL (seconds)
}
```

### Linux Kernel Tuning

```bash
# /etc/sysctl.conf
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
```

---

## 7. Production Deployment Checklist

### Pre-flight Checks

- [ ] Generate cluster secrets
- [ ] Configure Redis for shared state (if using)
- [ ] Set up monitoring (Prometheus endpoints)
- [ ] Configure log rotation
- [ ] Set file descriptor limits
- [ ] Test failure scenarios (node loss, network partition)

### Key Metrics to Monitor

- Cluster membership count
- Backend health scores
- Circuit breaker trips
- Request latency (p99)
- Active connections
- Rate limit hits

### Backup Strategy

```bash
# Backup certificates and configs
tar czf agbero-backup-$(date +%Y%m%d).tar.gz \
    /etc/agbero/agbero.hcl \
    /etc/agbero/hosts.d/ \
    /etc/agbero/certs.d/ \
    /var/lib/agbero/data.d/firewall.db
```

### Disaster Recovery

1. **Node Failure**: Cluster auto-heals, traffic redistributes
2. **Network Partition**: Nodes continue operating with local state
3. **Certificate Expiry**: Auto-renewal with 30-day window
4. **Full Cluster Loss**: Restore from backup, reseed

---

## 8. Troubleshooting Advanced Issues

### Cluster Issues

```bash
# Check cluster membership
curl localhost:9090/uptime | jq '.cluster'

# View gossip metrics
curl localhost:9090/debug/vars | grep gossip
```

### Health Score Investigation

```bash
# View detailed health metrics
curl localhost:9090/uptime | jq '.hosts[].routes[].backends[].health'
```

### Performance Profiling

```hcl
# Enable pprof in admin section
admin {
  pprof = true
}
```

```bash
# Collect profiles
go tool pprof http://localhost:9090/debug/pprof/heap
go tool pprof http://localhost:9090/debug/pprof/profile?seconds=30
```

---

## Next Steps

- **WebAssembly Plugins**: See [Plugin Guide](./plugin.md) for custom middleware
- **API Reference**: See [API Guide](./api.md) for programmatic control
- **Contributing**: See [Contributor Guide](./contributor.md)