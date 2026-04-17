# Agbero Advanced Guide

Deep dive into Agbero's advanced features: clustering, Git-based deployments, distributed state, and custom health scoring.

---

## 1. Clustering & Gossip

Agbero uses a hybrid clustering approach. It leverages HashiCorp's memberlist for UDP gossip (node discovery, status, locks, ACME challenges) and reliable TCP streams for large payloads (host configurations, TLS certificates). Keeper secrets are synchronised over the same encrypted gossip channel.

### Configuration

```hcl
# agbero.hcl
gossip {
  enabled    = true
  port       = 7946                           # UDP/TCP cluster port
  secret_key = "env.GOSSIP_SECRET"            # must be 16, 24, or 32 bytes — generate with: agbero secret cluster
  seeds      = ["node2:7946", "node3:7946"]   # Initial peers to join on startup
  ttl        = 30                             # Seconds before dead node removal

  # Shared state for distributed rate limiting & firewalls
  shared_state {
    enabled = true
    driver  = "redis"
    redis {
      host       = "redis.internal"
      port       = 6379
      password   = "env.REDIS_PASS"
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

Copy this value to `secret_key` in `agbero.hcl` on **every node**. All nodes in a cluster must use the same key.

### What Gets Synchronized

| Type | Protocol | Description |
|------|----------|-------------|
| Host Configs (`.hcl`) | TCP | Dynamic route definitions synced to `hosts.d/` |
| Certificates (`.crt`, `.key`) | TCP | Valid TLS certificates and encrypted private keys |
| Keeper Secrets | UDP gossip | Encrypted secrets broadcast when written on any node |
| ACME Challenges | UDP | Let's Encrypt HTTP-01 challenge tokens |
| Node Status | UDP | Node health, liveness, and draining status |
| Distributed Locks | UDP | Coordination primitives for single-node executions |

### Cluster Manager Implementation

The cluster manager is implemented in `internal/hub/cluster/` and provides:

- **Delegate**: Handles gossip events and state merging
- **Distributor**: Manages configuration file synchronization
- **Metrics**: Tracks cluster operations
- **Redis Shared State**: Distributed counters and rate limiting

---

## 2. Keeper — Encrypted Secret Store

The keeper is an encrypted, passphrase-protected database (`data.d/keeper.db`) that stores secrets, TLS certificates, the internal Ed25519 auth key, admin user credentials, and TOTP seeds. **It is a required component — Agbero will not start if the keeper cannot be opened.**

### Unlocking the Keeper

Agbero resolves the master passphrase in this order at startup:

1. `keeper.passphrase` in `agbero.hcl`
2. `AGBERO_PASSPHRASE` environment variable
3. Interactive terminal prompt (if running in a terminal)

For non-interactive environments (system service, container, CI):

```bash
# Set the passphrase as an environment variable
AGBERO_PASSPHRASE=mypassphrase agbero run

# Or configure it in agbero.hcl (use env var to avoid plaintext in file)
security {
  keeper {
    passphrase = "env.AGBERO_PASSPHRASE"  # reads from the environment
    auto_lock  = "2h"                      # lock after 2 hours of inactivity
    logging    = true                      # log keeper operations
    audit      = true                      # detailed audit trail
  }
}
```

### Secret References in Configuration

Any `Value`-typed field in your HCL can reference a keeper secret using the `ss://` scheme:

```hcl
# Instead of putting credentials directly in your config:
# headers = { "Authorization" = "Bearer sk_live_AbCdEf..." }  # BAD

# Or even in environment variables:
# headers = { "Authorization" = "Bearer env.STRIPE_KEY" }     # BETTER but still in process env

# Reference them from the keeper:
headers = {
  "Authorization" = "Bearer ss://integrations/stripe-key"    # BEST
}
```

Store the secret in the keeper:

```bash
agbero keeper set integrations/stripe-key "sk_live_AbCdEf..."
```

The `ss://namespace/key` reference is resolved at **request time** — the secret never appears in your config file, logs, or process arguments. This also means rotating a secret takes effect immediately on the next request without any reload or restart.

### First-time Setup

```bash
# 1. Scaffold the config directory
agbero init

# 2. Start Agbero — you will be prompted to create the master passphrase
agbero run

# 3. In subsequent runs, supply the passphrase via environment
AGBERO_PASSPHRASE=mypassphrase agbero run
```

See [Security Guide](./security.md) for the full Keeper REST API reference and [Command Guide](./command.md#keeper--encrypted-secret-store) for all keeper CLI operations.

---

### Secrets in a Cluster — Automatic Synchronisation

This is one of the most important things to understand when running Agbero in cluster mode: **keeper secrets are automatically synchronised across all nodes.**

#### How It Works

**On node join:** When a new node joins an existing cluster, the existing member includes an encrypted snapshot of all keeper secrets in its join state message. The joining node receives and decrypts the snapshot, writing every secret into its own local keeper. After joining, the new node has a complete copy of all secrets without any manual intervention.

**On secret write:** When any node writes a secret via `agbero keeper set` or `POST /api/v1/keeper/secrets`, the secret is immediately broadcast to all cluster peers via gossip as an `OpSecret` message. Each peer receives the encrypted message, decrypts it using the shared gossip cipher, and writes it to its local keeper. The deletion of a secret (`agbero keeper delete`, `DELETE /api/v1/keeper/secrets/...`) is similarly broadcast — every node removes the key from its local keeper.

**Propagation model:** Secret sync is eventually consistent (gossip, not Raft). There is a brief window (typically under a second on a LAN) after a write where other nodes may not yet have the new value. In practice this is not noticeable because secret reads happen from the local keeper on each node, not over the network.

#### Requirement: `secret_key` Must Be Set

Keeper secret synchronisation **requires** `secret_key` to be configured in the `gossip` block. Without a cipher, `BroadcastSecret` returns an error and secrets are only written locally — they do not propagate.

```hcl
gossip {
  enabled    = true
  secret_key = "env.GOSSIP_SECRET"   # REQUIRED for secret sync
  seeds      = ["node2:7946"]
}
```

If you write a secret and it doesn't appear on other nodes, check:
1. Is `secret_key` set on all nodes?
2. Is the key the same value on all nodes?
3. Check logs for `keeper: secret written locally but cluster broadcast failed`

#### Cluster Secret Sync Diagram

```
Node 1 (existing)          Node 2 (joining)
─────────────────          ────────────────
keeper.db:                 keeper.db: (empty)
  auth/jwt = "abc"
  stripe/key = "sk_..."

Node 2 joins →
  Node 1 sends encrypted
  keeper snapshot →         Receives snapshot
                            Decrypts with gossip key
                            Writes to local keeper.db:
                              auth/jwt = "abc"
                              stripe/key = "sk_..."

Later: agbero keeper set newns/newkey "value" (on Node 1)
  BroadcastSecret →         Receives OpSecret
                            Decrypts, writes to keeper.db:
                              newns/newkey = "value"
```

---

## 3. Git-Based Deployments (Cook)

Agbero includes "Cook" — an embedded GitOps engine for atomic static site deployments.

### How It Works

Agbero clones your repository to `work.d/{id}/deploy/{commit}`. It performs an atomic symlink swap to the `current` deployment, ensuring zero-downtime rollouts and instant rollbacks. The previous deployment is retained so a rollback is just swapping the symlink back.

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
      interval = "5m"            # Polling interval fallback (when no webhook)

      # Webhook secret (for push-to-deploy verification via HMAC)
      secret = "env.GITHUB_WEBHOOK_SECRET"

      auth {
        type               = "ssh-key"   # "basic", "ssh-key", "ssh-agent"
        username           = "git"
        ssh_key            = "ss://deploy/ssh-key"        # stored in keeper
        ssh_key_passphrase = "ss://deploy/ssh-passphrase" # stored in keeper
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

GitHub and GitLab both send compatible HMAC signatures. Point your webhook at this URL and set the same secret you configured in `secret`.

### Deployment Status

Check deployment health and current active commits via the uptime API:

```bash
curl http://localhost:9090/uptime | jq '.git'
```

**Example response:**
```json
{
  "frontend_app": {
    "state":        "healthy",
    "current_path": "/var/lib/agbero/work.d/frontend_app/deploy/a1b2c3d4/dist",
    "commit":       "a1b2c3d4e5f6g7h8i9j0",
    "deployments":  3
  }
}
```

### Manager Implementation

The cook manager (`internal/hub/cook/`) provides:
- Atomic symlink switching
- Webhook handling with HMAC verification
- Scheduled polling
- Deployment history and cleanup
- Support for multiple auth methods (basic, SSH key, SSH agent)

---

## 4. Health Scoring System

Unlike simple up/down binary checks, Agbero uses a 0–100 health score with four states to intelligently route traffic and drain failing backends.

### Health States

| State | Score Range | Traffic Weight | Description |
|-------|-------------|----------------|-------------|
| Healthy | 80–100 | 100% | Fully operational |
| Degraded | 50–79 | 50% | Performance issues detected |
| Unhealthy | 10–49 | 10% | Partial availability |
| Dead | 0–9 | 0% | Circuit broken, no traffic sent |

### Configuration

```hcl
# hosts.d/api.hcl
route "/api" {
  backend {
    server { address = "http://app:8080" }
  }

  health_check {
    enabled = true
    path    = "/health"
    interval = "10s"

    # Custom thresholds
    latency_baseline_ms     = 50    # 50ms baseline = 100% healthy
    latency_degraded_factor = 2.5   # >125ms (2.5×) reduces score

    # Advanced probing behavior
    accelerated_probing = true      # Probe aggressively when unhealthy
    synthetic_when_idle = true      # Probe even when no active traffic
  }
}
```

### Score Calculation

The health score combines multiple factors:

| Factor | Weight | Description |
|--------|--------|-------------|
| Latency | 40% | Response time relative to baseline |
| Success Rate | 30% | Active probe success/failure ratio |
| Passive Rate | 20% | Real request success rate |
| Connection Health | 10% | Connection pool health |

**Concrete example:** With `latency_baseline_ms = 50` and `latency_degraded_factor = 2.5`:
- A backend at 50ms → score ~100 (Healthy) → 100% of traffic
- A backend at 125ms (2.5×) → score ~65 (Degraded) → 50% of traffic
- A backend at 300ms (6×) → score ~30 (Unhealthy) → 10% of traffic
- A backend timing out → score ~5 (Dead) → 0% of traffic

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

## 5. Firewall & Rate Limiting

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
    mode    = "active"  # "active", "verbose", "monitor"

    inspect_body      = true
    max_inspect_bytes = 8192

    rule "rate-limit-abuse" {
      type   = "dynamic"
      action = "ban"
      duration = "24h"

      match {
        threshold {
          enabled  = true
          count    = 100
          window   = "1m"
          track_by = "ip"
        }
      }
    }

    rule "block-scanners" {
      type   = "static"
      action = "ban"

      match {
        any {
          location = "path"
          pattern  = ".*\\.(php|asp|aspx|jsp)$"
        }
        any {
          location = "header"
          key      = "User-Agent"
          pattern  = "(?i)(nikto|nmap|sqlmap)"
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
    enabled      = true
    status_code  = 403
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
curl http://localhost:9090/api/v1/firewall \
  -H "Authorization: Bearer ${TOKEN}"

# Manually ban an IP
curl -X POST http://localhost:9090/api/v1/firewall \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"ip": "1.2.3.4", "reason": "abuse", "duration_sec": 3600}'

# Unban an IP
curl -X DELETE "http://localhost:9090/api/v1/firewall?ip=1.2.3.4" \
  -H "Authorization: Bearer ${TOKEN}"
```

### Store Implementation

The firewall store (`internal/middleware/firewall/store.go`) uses:
- **bbolt** for persistent storage (bans survive restarts)
- **In-memory cache** for fast lookups on every request
- **Async writes** with batching for performance
- **Automatic expiration** of bans

---

## 6. Distributed Shared State

Agbero supports distributed rate limiting and firewalls using Redis so that limits are enforced globally across your cluster — not just per-node.

### Redis Configuration

```hcl
gossip {
  shared_state {
    enabled = true
    driver  = "redis"
    redis {
      host       = "redis.example.com"
      port       = 6379
      password   = "env.REDIS_PASSWORD"
      db         = 0
      key_prefix = "agbero:"
    }
  }
}
```

### Implementation

The Redis shared state (`internal/hub/cluster/state.go`) provides:

- **Atomic counters** using Redis INCR with Lua scripts
- **Token bucket rate limiting** with Redis
- **Prefix support** for multi-tenant deployments
- **Automatic connection pooling**

### Token Bucket Lua Script

```lua
local key          = KEYS[1]
local rate         = tonumber(ARGV[1])   -- tokens per second
local capacity     = tonumber(ARGV[2])   -- bucket capacity
local now          = tonumber(ARGV[3])   -- current time in seconds

local info         = redis.call("HMGET", key, "tokens", "last_refresh")
local tokens       = tonumber(info[1])
local last_refresh = tonumber(info[2])

if not tokens then
  tokens       = capacity
  last_refresh = now
end

local delta     = math.max(0, now - last_refresh)
local generated = delta * rate
tokens          = math.min(capacity, tokens + generated)

if tokens >= 1 then
  tokens = tokens - 1
  redis.call("HMSET", key, "tokens", tokens, "last_refresh", now)
  local ttl = math.ceil(capacity / rate) * 1000  -- convert to milliseconds for PEXPIRE
  if ttl > 0 then
    redis.call("PEXPIRE", key, ttl)
  end
  return 1
else
  return 0
end
```

---

## 7. Advanced TLS & Client Auth (mTLS)

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
| `request` | Request client cert, but don't require it |
| `require` | Require client cert, but don't verify against CA |
| `verify_if_given` | Verify if provided, but don't require |
| `require_and_verify` | Require and verify client cert against CA |

### Implementation

The TLS manager (`internal/hub/tlss/manager.go`) handles:
- **Dynamic certificate selection** based on SNI
- **mTLS configuration** per host
- **Certificate caching** with LRU
- **Automatic renewal** for expiring certs
- **Cluster synchronisation** of certificates

---

## 8. Certificate Management

### Local Development CA

```bash
# Install local CA for development (trusted by browsers)
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
  enabled     = true
  email       = "admin@example.com"
  staging     = false        # Use staging CA for testing
  short_lived = false        # Request short-lived certs
}
```

### Certificate Storage

Certificates are stored in `certs.d/` with optional encryption:

- `domain.crt` — Public certificate
- `domain.key` — Private key (encrypted when keeper is configured)
- `ca-cert.pem` — Local CA certificate
- `ca-key.pem` — Local CA private key
- `acme_account` — ACME account key

### Cluster Certificate Sync

When clustering is enabled, certificates are automatically synchronized across all nodes using encrypted TCP transport.

---

## 9. Performance Tuning

### Global Settings

```hcl
# agbero.hcl
general {
  max_header_bytes = 2097152  # 2MB
}

timeouts {
  read  = "60s"
  write = "60s"
  idle  = "300s"  # Longer keep-alive for persistent connections
}
```

### Transport Configuration

The HTTP transport is configured in `internal/hub/resource/manager.go` with high-throughput defaults:

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

---

## 10. Telemetry & Monitoring

### Built-in Telemetry

```hcl
telemetry {
  enabled = true  # Off by default
}
```

When enabled, samples metrics every 60 seconds and retains 24 hours of history:

```bash
# Query telemetry data
curl "http://localhost:9090/api/v1/telemetry/history?host=example.com&range=1h" \
  -H "Authorization: Bearer ${TOKEN}"
```

**Response:**
```json
{
  "host":  "example.com",
  "range": "1 hour",
  "samples": [
    {
      "ts":              1710501000,
      "requests_sec":    1250.5,
      "p99_ms":          45.2,
      "error_rate":      0.5,
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
    path    = "/metrics"
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
    enabled    = true
    url        = "http://victoria:8428/api/v1/write"
    batch_size = 500
  }
}
```

---

## 11. Advanced Load Balancing Strategies

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
    keys     = ["header:X-API-Key", "ip"]  # Fallback keys in order

    server { address = "http://cache-1:8080" }
    server { address = "http://cache-2:8080" }
    server { address = "http://cache-3:8080" }
  }
}
```

### Adaptive Load Balancing

The adaptive strategy uses epsilon-greedy exploration to learn which backend performs best over time. It tracks response time and in-flight requests to calculate a score. Lower score wins:

```
score = responseTime × (1.0 + inflight × 0.1)
```

Over time, the strategy naturally routes more traffic to faster backends while still occasionally probing slower ones in case they recover.

---

## 12. Path Matching & Routing

Agbero uses a radix tree for high-performance path matching with support for:

### Literal Paths
```hcl
route "/users/profile" { ... }
```

### Template Parameters
```hcl
route "/users/{id}" { ... }
route "/users/{id:[0-9]+}" { ... }  # With inline regex constraint
```

### Wildcard/Catch-all
```hcl
route "/*" { ... }  # Catch-all — must be last
```

### Regex Patterns
```hcl
route "~ ^/api/v[0-9]/.*$" { ... }  # Regex with ~ prefix
```

### Priority Order
1. Literal paths (highest priority)
2. Template parameters
3. Regex patterns
4. Catch-all (lowest priority)

---

## 13. TCP Health Checks

Implement custom health check logic for non-HTTP backends:

```hcl
proxy "redis" {
  enabled  = true
  listen   = ":6379"

  health_check {
    enabled  = true
    interval = "5s"
    timeout  = "1s"
    send     = "PING\r\n"
    expect   = "+PONG"
  }

  backend { address = "tcp://redis-1:6379" }
}
```

---

## 14. Replay — Outbound Domain Security (`allowed_domains`)

When using `replay` blocks in relay mode (where the target URL is supplied by the client at request time via the `X-Agbero-Replay-Url` header or `?url=` query parameter), you **must** configure `allowed_domains` to prevent Server-Side Request Forgery (SSRF).

**The attack without protection:** A malicious client or an XSS victim's browser could send `POST /proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name` and receive your cloud provider's IAM credentials in the response. Private IPs (127.x, 10.x, 192.168.x, 172.16–31.x) are always blocked as a backstop, but external attacker-controlled domains are not — hence `allowed_domains`.

```hcl
route "/proxy" {
  serverless {
    enabled = true

    replay "safe-proxy" {
      enabled = true

      # Only allow requests to these domains — blocks everything else
      allowed_domains = [
        "api.stripe.com",     # exact match
        "*.sendgrid.com",     # wildcard subdomain
        "api.github.com",
      ]

      # Private and loopback IPs (127.x, 10.x, 192.168.x, etc.) are
      # ALWAYS blocked regardless of this list — this is a safety backstop
    }
  }
}
```

> **Warning:** Setting `allowed_domains = ["*"]` allows all external domains. This defeats the SSRF protection — **never use `"*"` in production**.

---

## Next Steps

- **API Reference**: See [API Guide](./api.md) for dynamic route management and the full Keeper API
- **Plugin Development**: See [Plugin Guide](./plugin.md) for WASM
- **Contributing**: See [Contributor Guide](./contributor.md) for development
