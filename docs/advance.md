# Agbero Advanced Guide

Deep dive into Agbero's advanced features: clustering, Git-based deployments, distributed state, and custom health scoring.

## 1. Clustering & Gossip

Agbero uses a hybrid clustering approach. It leverages HashiCorp's memberlist for UDP gossip (node discovery, status, locks, ACME challenges) and reliable TCP streams for large payloads (host configurations, TLS certificates).

### Configuration

```hcl
# agbero.hcl
gossip {
  enabled    = true
  port       = 7946                           # UDP/TCP cluster port
  secret_key = "env.GOSSIP_SECRET"               # 16, 24, or 32 raw bytes
  seeds      = ["node2:7946", "node3:7946"]   # Initial peers
  ttl        = 30                             # Seconds before dead node removal

  # Shared state for distributed rate limiting & firewalls
  shared_state {
    enabled = true
    driver  = "redis"
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

### Secret Key Generation

Generate a secure 32-byte key for gossip encryption:

```bash
agbero secret cluster
# Output: b64.xVZ9k2mN8pQrS4tU6vW8xY0zA1bC3dE5fG7hI9jK=
```

### What Gets Synchronized

| Type | Protocol | Description |
|------|----------|-------------|
| Host Configs (`.hcl`) | TCP | Dynamic route definitions synced to `hosts.d/` |
| Certificates (`.crt`, `.key`) | TCP | Valid TLS certificates and encrypted private keys |
| ACME Challenges | UDP | Let's Encrypt HTTP-01 challenge tokens |
| Node Status | UDP | Node health, liveness, and draining status |
| Distributed Locks | UDP | Coordination primitives for single-node executions |

### Cluster Manager Implementation

The cluster manager is implemented in `internal/cluster/` and provides:

- **Delegate**: Handles gossip events and state merging
- **Distributor**: Manages configuration file synchronization
- **Metrics**: Tracks cluster operations
- **Redis Shared State**: Distributed counters and rate limiting

---

## 2. Git-Based Deployments (Cook)

Agbero includes "Cook" - an embedded GitOps engine for atomic static site deployments.

### How It Works

Agbero clones your repository to `work.d/{id}/deploy/{commit}`. It performs an atomic symlink swap to the `current` deployment, ensuring zero-downtime rollouts and instant rollbacks.

### Configuration

```hcl
# hosts.d/frontend.hcl
route "/" {
  web {
    git {
      enabled  = true
      id       = "frontend_app"
      url      = "git@github.com:org/frontend.git"
      branch   = "main"
      sub_dir  = "dist"          # Serve a specific folder inside the repo
      interval = "30s"           # Polling interval fallback
      
      # Webhook secret (for push-to-deploy verification)
      secret = "${env.GITHUB_WEBHOOK_SECRET}"
      
      auth {
        type = "ssh-key"         # "basic", "ssh-key", "ssh-agent"
        username = "git"
        ssh_key = "env.PRIVATE_KEY"
        ssh_key_passphrase = "env.SSH_PASSPHRASE"
      }
    }
  }
}
```

### Webhook Endpoint

Trigger deployments instantly by pointing your Git provider to Agbero's webhook endpoint:

```bash
POST /.well-known/agbero/webhook/git/frontend_app
Headers:
  X-Hub-Signature-256: sha256=<hmac>
  X-GitHub-Event: push
```

### Deployment Status

Check deployment health and current active commits via the uptime API:

```bash
curl http://localhost:9090/uptime | jq '.git'
```

**Example response:**
```json
{
  "frontend_app": {
    "state": "healthy",
    "current_path": "/var/lib/agbero/work.d/frontend_app/deploy/a1b2c3d4/dist",
    "commit": "a1b2c3d4e5f6g7h8i9j0",
    "deployments": 3
  }
}
```

### Manager Implementation

The cook manager (`internal/pkg/cook/`) provides:
- Atomic symlink switching
- Webhook handling with HMAC verification
- Scheduled polling
- Deployment history and cleanup
- Support for multiple auth methods (basic, SSH key, SSH agent)

---

## 3. Health Scoring System

Unlike simple up/down binary checks, Agbero uses a 0-100 health score with four states to intelligently route traffic and drain failing backends.

### Health States

| State | Score Range | Traffic Weight | Description |
|-------|-------------|----------------|-------------|
| Healthy | 80-100 | 100% | Fully operational |
| Degraded | 50-79 | 50% | Performance issues |
| Unhealthy | 10-49 | 10% | Partial availability |
| Dead | 0-9 | 0% | Circuit broken |

### Configuration

```hcl
# hosts.d/api.hcl
route "/api" {
  backend {
    server { address = "http://app:8080" }
  }

  health_check {
    enabled = true
    path = "/health"
    interval = "10s"
    
    # Custom thresholds
    latency_baseline_ms = 50      # 50ms baseline is 100% healthy
    latency_degraded_factor = 2.5 # >125ms reduces score
    
    # Advanced probing behavior
    accelerated_probing = true    # Probe aggressively when unhealthy
    synthetic_when_idle = true    # Probe even when no active traffic
  }
}
```

### Score Calculation

The health score combines multiple factors:

| Factor | Weight | Description |
|--------|--------|-------------|
| Latency | 40% | Response time relative to baseline |
| Success Rate | 30% | Active probe success/failure |
| Passive Rate | 20% | Real request success rate |
| Connection Health | 10% | Connection pool health |

### Early Abort Controller

Prevents requests to rapidly deteriorating backends:

```go
// Implemented in internal/pkg/health/abort.go
if score.IsRapidDeterioration() {
    // Abort before dialing
    return fallback
}
```

---

## 4. Firewall & Rate Limiting

Agbero includes a robust Web Application Firewall (WAF) and Rate Limiter capable of using memory or distributed Redis for global enforcement.

### Rate Limit Policies

```hcl
# agbero.hcl (Global definitions)
rate_limits {
  enabled = true

  policy "api-strict" {
    requests = 10
    window   = "1m"
    burst    = 15
    key      = "X-API-Key"   # header name; omit for IP-based
  }

  policy "api-lenient" {
    requests = 1000
    window   = "1h"
    burst    = 200
  }
}
```

### Dynamic Firewall Rules

```hcl
security {
  enabled = true
  firewall {
    enabled = true
    mode = "active"  # "active", "verbose", "monitor"
    
    inspect_body = true
    max_inspect_bytes = 8192
    
    rule "rate-limit-abuse" {
      type = "dynamic"
      action = "ban"
      duration = "24h"
      
      match {
        threshold {
          enabled = true
          count = 100
          window = "1m"
          track_by = "ip"
        }
      }
    }
    
    rule "block-scanners" {
      type = "static"
      action = "ban"
      
      match {
        any {
          location = "path"
          pattern = ".*\\.(php|asp|aspx|jsp)$"
        }
        any {
          location = "header"
          key = "User-Agent"
          pattern = "(?i)(nikto|nmap|sqlmap)"
        }
      }
    }
  }
}
```

### Firewall Actions

```hcl
action "ban" {
  mitigation = "add"  # "add" adds to persistent ban store
  response {
    enabled = true
    status_code = 403
    content_type = "application/json"
    body_template = "{\"error\": \"Access Denied\"}"
    headers = {
      "X-Block-Reason" = "WAF"
    }
  }
}
```

### Firewall Management API

```bash
# List active bans
curl http://localhost:9090/firewall

# Manually ban an IP
curl -X POST http://localhost:9090/firewall \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{"ip": "1.2.3.4", "reason": "abuse", "duration_sec": 3600}'

# Unban an IP
curl -X DELETE "http://localhost:9090/firewall?ip=1.2.3.4"
```

### Store Implementation

The firewall store (`internal/middleware/firewall/store.go`) uses:
- **bbolt** for persistent storage
- **In-memory cache** for fast lookups
- **Async writes** with batching for performance
- **Automatic expiration** of bans

---

## 5. Distributed Shared State

Agbero supports distributed rate limiting and firewalls using Redis.

### Redis Configuration

```hcl
gossip {
  shared_state {
    enabled = true
    driver = "redis"
    redis {
      host = "redis.example.com"
      port = 6379
      password = "${env.REDIS_PASSWORD}"
      db = 0
      key_prefix = "agbero:"
    }
  }
}
```

### Implementation

The Redis shared state (`internal/cluster/state.go`) provides:

- **Atomic counters** using Redis INCR with Lua scripts
- **Token bucket rate limiting** with Redis
- **Prefix support** for multi-tenant deployments
- **Automatic connection pooling**

### Lua Script for Rate Limiting

```lua
local key = KEYS[1]
local rate = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

local info = redis.call("HMGET", key, "tokens", "last_refresh")
local tokens = tonumber(info[1])
local last_refresh = tonumber(info[2])

if not tokens then
    tokens = capacity
    last_refresh = now
end

local delta = math.max(0, now - last_refresh)
local generated = delta * rate
tokens = math.min(capacity, tokens + generated)

if tokens >= 1 then
    tokens = tokens - 1
    redis.call("HMSET", key, "tokens", tokens, "last_refresh", now)
    local ttl = math.ceil(capacity / rate)
    if ttl > 0 then
        redis.call("PEXPIRE", key, ttl)
    end
    return 1
else
    return 0
end
```

---

## 6. Advanced TLS & Client Auth (mTLS)

Require and verify client certificates before allowing traffic to your backends.

### Configuration

```hcl
# hosts.d/internal.hcl
domains = ["secure.internal"]

tls {
  mode = "local"
  local {
    cert_file = "/etc/certs/server.crt"
    key_file  = "/etc/certs/server.key"
  }
  
  client_auth = "require_and_verify"  # "none", "request", "require",
                                      # "verify_if_given", "require_and_verify"
  client_cas  = ["/etc/certs/ca.crt"]  # Absolute paths to CA certificates
}

route "/" {
  backend {
    server { address = "http://internal-service:8080" }
  }
}
```

### Client Auth Modes

| Mode | Description |
|------|-------------|
| `none` | No client certificate requested |
| `request` | Request client cert, but don't require |
| `require` | Require client cert, but don't verify |
| `verify_if_given` | Verify if provided, but don't require |
| `require_and_verify` | Require and verify client cert |

### Implementation

The TLS manager (`internal/pkg/tlss/manager.go`) handles:
- **Dynamic certificate selection** based on SNI
- **mTLS configuration** per host
- **Certificate caching** with LRU
- **Automatic renewal** for expiring certs
- **Cluster synchronization** of certificates

---

## 7. Certificate Management

### Local Development CA

```bash
# Install local CA for development
agbero cert install

# List managed certificates
agbero cert list

# Show certificate info
agbero cert info

# Uninstall CA
agbero cert uninstall
```

### Let's Encrypt Integration

```hcl
letsencrypt {
  enabled = true
  email = "admin@example.com"
  staging = false  # Use staging CA for testing
  short_lived = false  # Request short-lived certs
}
```

### Certificate Storage

Certificates are stored in `certs.d/` with optional encryption:

- `domain.crt` - Public certificate
- `domain.key` - Private key (plaintext or encrypted with `.enc` suffix)
- `ca-cert.pem` - Local CA certificate
- `ca-key.pem` - Local CA private key
- `acme_account` - ACME account key

### Cluster Certificate Sync

When clustering is enabled, certificates are automatically synchronized across all nodes using encrypted TCP transport.

---

## 8. Performance Tuning

### Global Settings

```hcl
# agbero.hcl
general {
  max_header_bytes = 2097152  # 2MB
}

timeouts {
  read = "60s"
  write = "60s"
  idle = "300s"  # Longer keep-alive
}
```

### Transport Configuration

The HTTP transport is configured in `internal/core/resource/manager.go` with high-throughput defaults:

```go
&http.Transport{
    MaxIdleConns:          10000,
    MaxIdleConnsPerHost:   10000,
    IdleConnTimeout:       90 * time.Second,
    TLSHandshakeTimeout:   5 * time.Second,
    ResponseHeaderTimeout: 5 * time.Second,
    ExpectContinueTimeout: 1 * time.Second,
}
```

### Cache Sizes

```hcl
# Resource manager cache sizes (internal - not configurable in HCL)
route_cache_size = 10000
tcp_cache_size   = 10000
auth_cache_size  = 100000
gz_cache_size    = 256
```

---

## 9. Telemetry & Monitoring

### Built-in Telemetry

```hcl
telemetry {
  enabled = true  # Off by default
}
```

When enabled, samples metrics every 60 seconds and retains 24 hours of history:

```bash
# Query telemetry data
curl "http://localhost:9090/telemetry/history?host=example.com&range=1h"
```

**Response:**
```json
{
  "host": "example.com",
  "range": "1 hour",
  "samples": [
    {
      "ts": 1710501000,
      "requests_sec": 1250.5,
      "p99_ms": 45.2,
      "error_rate": 0.5,
      "active_backends": 3
    }
  ]
}
```

### Prometheus Metrics

```hcl
logging {
  prometheus {
    enabled = true
    path = "/metrics"
  }
}
```

Available metrics:
- `agbero_http_requests_total`
- `agbero_http_request_duration_seconds`
- `agbero_last_request_timestamp_seconds`
- `agbero_active_connections`
- `agbero_circuit_breaker_tripped_total`

### VictoriaMetrics Integration

```hcl
logging {
  victoria {
    enabled = true
    url = "http://victoria:8428/api/v1/write"
    batch_size = 500
  }
}
```

---

## 10. Advanced Load Balancing Strategies

| Strategy | Description | Use Case |
|----------|-------------|----------|
| `round_robin` | Simple rotation | General purpose |
| `least_conn` | Least active connections | Long-lived connections |
| `random` | Random selection | Testing |
| `ip_hash` | Hash client IP | Session affinity |
| `url_hash` | Hash URL path | Cache affinity |
| `weighted_least_conn` | Weighted by capacity | Heterogeneous backends |
| `least_response_time` | Fastest response | Latency-sensitive |
| `power_of_two` | Pick two, choose better | High performance |
| `consistent_hash` | Minimal redistribution | Cache clusters |
| `adaptive` | Learn and adapt | Dynamic environments |
| `sticky` | Session persistence | User sessions |

### Consistent Hashing

```hcl
route "/cache" {
  backend {
    strategy = "consistent_hash"
    keys = ["header:X-API-Key", "ip"]  # Fallback keys
    
    server { address = "http://cache-1:8080" }
    server { address = "http://cache-2:8080" }
    server { address = "http://cache-3:8080" }
  }
}
```

### Adaptive Load Balancing

The adaptive strategy uses epsilon-greedy exploration to learn optimal backend selection:

```go
// From internal/pkg/lb/adaptive.go
score := responseTime * (1.0 + inflight*0.1)
// Lower score wins
```

---

## 11. Path Matching & Routing

Agbero uses a radix tree for high-performance path matching with support for:

### Literal Paths
```hcl
route "/users/profile" { ... }
```

### Template Parameters
```hcl
route "/users/{id}" { ... }
route "/users/{id:[0-9]+}" { ... }  # With regex
```

### Wildcard/Catch-all
```hcl
route "/*" { ... }  # Catch-all at end
```

### Regex Patterns
```hcl
route "~ ^/api/v[0-9]/.*$" { ... }  # Regex with ~ prefix
```

### Priority Order
1. Literal paths (highest)
2. Template parameters
3. Regex patterns
4. Catch-all (lowest)

---

## 12. Health Check Executors

Implement custom health check logic for non-HTTP backends:

### TCP Health Check

```hcl
proxy "redis" {
  listen = ":6379"
  
  health_check {
    enabled = true
    interval = "5s"
    timeout = "1s"
    send = "PING\r\n"
    expect = "+PONG"
  }
  
  backend { address = "tcp://redis-1:6379" }
}
```

### Custom Executor Interface

```go
type Executor interface {
    Probe(ctx context.Context) (success bool, latency time.Duration, err error)
}
```

---

## Next Steps

- **API Reference**: See [API Guide](./api.md) for dynamic route management
- **Plugin Development**: See [Plugin Guide](./plugin.md) for WASM
- **Contributing**: See [Contributor Guide](./contributor.md) for development