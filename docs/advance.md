# Agbero Advanced Guide

Deep dive into Agbero's advanced features: clustering, Git-based deployments, WASM middleware, distributed state, and custom health scoring.

## 1. Clustering & Gossip

Agbero uses a hybrid clustering approach. It leverages HashiCorp's memberlist for UDP gossip (node discovery, status, locks, ACME challenges) and reliable TCP streams for large payloads (host configurations, TLS certificates).

### Configuration

```hcl
# agbero.hcl
gossip {
  enabled    = true
  port       = 7946                           # UDP/TCP cluster port
  secret_key = "${env.GOSSIP_SECRET}"         # 16/24/32 bytes or base64 encoded
  seeds      =["node2:7946", "node3:7946"]   # Initial peers
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

Agbero cluster traffic is encrypted using XChaCha20-Poly1305. Generate a secure key using the CLI:

```bash
agbero cluster secret
# Output: b64.YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
```

### What Gets Synchronized

| Type | Protocol | Description |
|------|----------|-------------|
| Host Configs (`.hcl`) | TCP | Dynamic route definitions synced directly to `hosts.d/` |
| Certificates (`.crt`) | TCP | Valid TLS certificates and encrypted private keys |
| ACME Challenges | UDP | Let's Encrypt HTTP-01 challenge tokens |
| Node Status | UDP | Node health, liveness, and draining status |
| Distributed Locks | UDP | Coordination primitives for single-node executions |

## 2. Git-Based Deployments (Cook)

Agbero includes "Cook" - an embedded GitOps engine for atomic static site deployments.

### How It Works

Agbero clones your repository to `work.d/{id}/deploy/{commit}` (or `root/deploy/{commit}` if `root` is specified). It performs an atomic symlink swap to the `current` deployment, ensuring zero-downtime rollouts and instant rollbacks.

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
        type = "ssh-key"
        ssh_key = "${b64.PRIVATE_KEY_BASE64}"
      }
    }
  }
}
```

### Webhook Endpoint

Trigger deployments instantly by pointing your Git provider to Agbero's webhook endpoint:

```text
POST /.well-known/agbero/webhook/git/frontend_app
Headers:
  X-Hub-Signature-256: sha256=<hmac>
```

### Deployment Status

Check deployment health and current active commits via the uptime API:

```bash
curl http://localhost:9090/uptime | jq '.git'
```

## 3. Gradient Health Scoring

Unlike simple up/down binary checks, Agbero uses a 0-100 health score with four states to intelligently route traffic and drain failing backends.

| State | Score | Traffic Weight | Behavior |
|-------|-------|----------------|----------|
| Healthy | 100-80 | 100% | Full traffic |
| Degraded | 79-50 | 50% | Reduced weight |
| Unhealthy | 49-10 | 10% | Minimal traffic |
| Dead | 9-0 | 0% | No traffic (Circuit Broken) |

### Custom Configuration

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
    key      = "ip"
  }
  
  policy "api-lenient" {
    requests = 1000
    window   = "1h"
    burst    = 200
    key      = "header:X-API-Key"
  }
}
```

### Dynamic Firewall Rules

```hcl
security {
  enabled = true
  firewall {
    enabled = true
    mode = "active"
    
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

## 5. WebAssembly (WASM) Middleware

Inject custom, highly performant middleware written in Go or Rust directly into the request pipeline.

```hcl
route "/filter" {
  wasm {
    enabled = true
    module = "/etc/agbero/wasm/filter.wasm"
    
    # Security: Explicitly grant capabilities
    access = ["headers", "config"]
    
    config = {
      "block_countries" = "CN,RU"
    }
  }
  
  backend {
    server { address = "http://app:8080" }
  }
}
```

## 6. Advanced TLS & Client Auth (mTLS)

Require and verify client certificates before allowing traffic to your backends.

```hcl
# hosts.d/internal.hcl
domains = ["secure.internal"]

tls {
  mode = "local"
  local {
    cert_file = "/etc/certs/server.crt"
    key_file  = "/etc/certs/server.key"
  }
  
  client_auth = "require_and_verify"
  client_cas  = ["/etc/certs/ca.crt"]
}
```

## 7. Performance & System Limits

Optimize Agbero for high-throughput production environments.

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

logging {
  level = "info"
  deduplicate = true  # Reduce log spam
  
  # Export to VictoriaMetrics
  victoria {
    enabled = true
    url = "http://victoria:8428/api/v1/write"
    batch_size = 500
  }
  
  # Expose Prometheus endpoint
  prometheus {
    enabled = true
    path = "/metrics"
  }
}
```