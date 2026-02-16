# Agbero Guide: Practical Examples & Use Cases

This guide provides practical examples, use cases, and deep dives into Agbero's capabilities.

## Why Agbero? Solving Real Problems

### The Problem with Traditional Proxies

Traditional proxies like Nginx and Caddy often fall short in modern microservices environments:

1. **Static Configuration**: Most require manual reloads and restarts for service discovery
2. **Complex Service Discovery**: Integrating with service meshes requires plugins and extra tooling
3. **Poor Developer Experience**: Local development TLS setup is cumbersome
4. **Limited Observability**: Basic metrics without detailed latency histograms
5. **No Built-in Gossip**: Manual coordination for multi-node setups

### How Agbero Solves These Issues

> *As referenced in [this Twitter thread](https://x.com/ayushagarwal/status/2016439436192751948?s=46), developers need tools that bridge local development and production seamlessly.*

**Agbero provides**:  
✅ Zero-config local development with auto-TLS  
✅ Production-grade load balancing with zero-downtime updates  
✅ Built-in gossip for automatic service discovery  
✅ Unified configuration from development to production

## 🚀 Practical Examples

### 1. Zero-Config Local Development

**Problem**: Setting up HTTPS for local development is painful.

**Solution**: Agbero's "Smart TLS":

```bash
# Just run this in any directory
agbero run

# What happens automatically:
# 1. Generates config.hcl if missing
# 2. Creates local CA certificate (if not installed)
# 3. Generates TLS certificate for localhost
# 4. Serves current directory on https://localhost:8443
```

**Behind the scenes**: Agbero uses `mkcert`-style certificates but without requiring you to install anything. The CA is automatically added to your system's trust store.

### 2. Multi-Service Local Development

**Problem**: You have multiple services (frontend, API, database UI) running on different ports.

**Solution**: Single proxy entry point:

```hcl
# hosts.d/frontend.hcl
domains = ["app.localhost"]

route "/" {
  web {
    root = "./frontend/dist"
  }
}

# hosts.d/api.hcl  
domains = ["api.localhost"]

route "/" {
  backend {
    server {
      address = "http://localhost:3001"
    }
  }
}

# hosts.d/adminer.hcl
domains = ["db.localhost"]

route "/" {
  backend {
    server {
      address = "http://localhost:8080"
    }
  }
}
```

**Result**: `https://app.localhost`, `https://api.localhost`, `https://db.localhost` all with valid TLS certificates.

### 3. Canary Deployments

**Problem**: Safely rolling out new versions to production.

**Solution**: Weighted load balancing:

```hcl
route "/api" {
  backend {
    strategy = "weighted_round_robin"

    # Stable version - 90% traffic
    server {
      address = "http://v1-cluster:8080"
      weight  = 90
    }

    # Canary version - 10% traffic
    server {
      address = "http://v2-canary:8080"
      weight  = 10
      conditions {
        source_ips = ["10.0.0.100"]  # Internal testers
      }
    }
  }

  health_check {
    path     = "/health"
    interval = "30s"
  }

  circuit_breaker {
    threshold = 5  # Trip after 5 consecutive failures
  }
}
```

### 4. JWT Authentication Gateway

**Problem**: You need to validate JWTs and extract claims before forwarding to services.

**Solution**: Built-in JWT middleware:

```hcl
route "/protected" {
  jwt_auth {
    secret = "${env.JWT_SECRET}"
    issuer = "my-app"

    claim_map = {
      "user_id"   = "X-User-ID"
      "user_role" = "X-User-Role"
    }
  }

  backend {
    server {
      address = "http://backend-service:8080"
    }
  }
}
```

**What happens**:
1. JWT validated on `Authorization: Bearer <token>` header
2. Claims extracted and added as headers (`X-User-ID`, `X-User-Role`)
3. Request forwarded to backend with enriched headers

### 5. Forward Auth Implementation in Go

**Problem**: You need to integrate with an external authentication service.

**Agbero solution**:

```hcl
route "/admin" {
  forward_auth {
    url = "http://auth-service:9000/verify"

    # Headers to forward to auth service
    request_headers = ["Authorization", "Cookie", "X-Original-URI"]

    # Headers to copy from auth response to backend
    auth_response_headers = ["X-User-Email", "X-User-Roles"]

    on_failure = "deny"  # or "allow" for fail-open
  }

  backend {
    server {
      address = "http://admin-dashboard:8080"
    }
  }
}
```

**Implementing your own auth service in Go**:

```go
package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

func main() {
	http.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")

		// Validate token (example using a simple JWT library)
		isValid, claims := validateToken(token)
		if !isValid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Set caching headers (Agbero will cache successful auth)
		w.Header().Set("Cache-Control", "max-age=300")

		// Set headers that will be forwarded to the backend
		w.Header().Set("X-User-Email", claims["email"])
		w.Header().Set("X-User-Roles", strings.Join(claims["roles"], ","))

		// Return 200 OK - Agbero will forward with headers
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "authorized",
		})
	})

	http.ListenAndServe(":9000", nil)
}
```

### 6. Dynamic Service Discovery with Gossip

You're absolutely right. Let me separate this clearly and remove Docker to focus on the core concepts:

#### Method 1: HTTP Discovery (Simple)
Agbero periodically polls HTTP endpoints to discover services. This is the simplest approach.

###3 Method 2: Direct Gossip Integration (Advanced)
Services embed Memberlist and join the gossip cluster directly for real-time updates.

---

### Method 1: HTTP Discovery (Recommended for most services)

This method requires no code changes to your service. Agbero discovers services by polling their HTTP endpoints.

#### How it works:
1. Agbero scans for services exposing a `/.well-known/agbero` endpoint
2. Fetches service metadata including the route configuration
3. Adds the service to the load balancer pool

#### Service requirements:
```go
package main

import (
	"encoding/json"
	"net/http"
)

func main() {
	// Your existing HTTP handlers
	http.HandleFunc("/api/users", handleUsers)
	http.HandleFunc("/api/orders", handleOrders)

	// Required: Agbero discovery endpoint
	http.HandleFunc("/.well-known/agbero", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"host":   "myapp.localhost",  // Domain Agbero should route to
			"port":   8080,               // Service port
			"path":   "/api",             // Route path prefix
			"token":  "YOUR_JWT_TOKEN",   // From 'agbero gossip token'
			"weight": 10,                 // Load balancing weight
		})
	})

	// Optional but recommended: Health endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	http.ListenAndServe(":8080", nil)
}
```

**Advantages:**
- Zero dependencies on Memberlist
- Works with any HTTP service (Go, Python, Node.js, etc.)
- Simple to implement

**Limitations:**
- Polling-based (default: 30-second intervals)
- Not real-time

---

### Method 2: Direct Gossip Integration (Real-time)

For real-time service discovery, embed Memberlist directly in your Go service.

#### Prerequisite: Generate a token
```bash
# On the Agbero proxy node
agbero gossip token --service my-service --ttl 720h > token.txt
```

#### Complete Go service with Memberlist:

```go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/hashicorp/memberlist"
)

// Metadata that Agbero expects
type ServiceMeta struct {
	Token       string `json:"token,omitempty"`
	Port        int    `json:"port"`
	Host        string `json:"host"`
	Path        string `json:"path"`
	StripPrefix bool   `json:"strip,omitempty"`
	Weight      int    `json:"weight,omitempty"`
	HealthPath  string `json:"health_path,omitempty"`
}

// Memberlist delegate to provide metadata
type metaDelegate struct {
	metadata []byte
}

func (d *metaDelegate) NodeMeta(limit int) []byte {
	if len(d.metadata) > limit {
		return d.metadata[:limit]
	}
	return d.metadata
}

func (d *metaDelegate) NotifyMsg([]byte)                           {}
func (d *metaDelegate) GetBroadcasts(overhead, limit int) [][]byte { return nil }
func (d *metaDelegate) LocalState(join bool) []byte                { return nil }
func (d *metaDelegate) MergeRemoteState(buf []byte, join bool)     {}

func main() {
	// 1. Read token generated by Agbero
	token, err := os.ReadFile("token.txt")
	if err != nil {
		log.Fatalf("Failed to read token: %v", err)
	}

	// 2. Define service metadata
	meta := ServiceMeta{
		Token:       string(token),
		Port:        8080,
		Host:        "myapp.internal",
		Path:        "/api",
		StripPrefix: true,
		Weight:      10,
		HealthPath:  "/health",
	}

	metaJSON, _ := json.Marshal(meta)

	// 3. Start HTTP server
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello from service"))
		})
		mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		http.ListenAndServe(fmt.Sprintf(":%d", meta.Port), mux)
	}()

	// 4. Configure Memberlist
	config := memberlist.DefaultLANConfig()
	config.Name = fmt.Sprintf("service-%d", meta.Port)
	config.BindPort = 0  // Auto-select port
	config.Delegate = &metaDelegate{metadata: metaJSON}
	config.PushPullInterval = 30 * time.Second

	// 5. Create and join cluster
	list, err := memberlist.Create(config)
	if err != nil {
		log.Fatal("Memberlist create failed:", err)
	}
	defer list.Shutdown()

	// Join Agbero's gossip cluster
	seeds := []string{"agbero-host:7946"}  // Agbero's gossip port
	if _, err := list.Join(seeds); err != nil {
		log.Printf("Warning: Could not join gossip: %v", err)
	}

	log.Println("Service running with gossip integration")

	// 6. Keep running
	select {}
}
```

#### How it works:
1. **Token Authentication**: Services authenticate with JWT tokens generated by Agbero
2. **Metadata Broadcast**: Services broadcast their routing metadata via gossip
3. **Real-time Updates**: Agbero receives updates within seconds via UDP gossip
4. **Automatic Health Checks**: Agbero monitors service health and removes failed instances

**Advantages:**
- Real-time service discovery (sub-second updates)
- Automatic failure detection via gossip
- No polling overhead
- Built-in encryption support

**Limitations:**
- Go-only (requires Memberlist library)
- Adds complexity to services
- Requires UDP port (7946) open between services

---

### Which Method Should You Use?

| Use Case | Recommended Method |
|----------|-------------------|
| **Simple microservices** | HTTP Discovery |
| **Polyglot environment** | HTTP Discovery |
| **Real-time scaling needs** | Direct Gossip |
| **High-availability clusters** | Direct Gossip |
| **Legacy services** | HTTP Discovery |
| **New Go services** | Direct Gossip |

#### Hybrid Approach
You can mix both methods in the same cluster. Some services use HTTP discovery, others use direct gossip.

---

## Configuration Examples

### Agbero Configuration (`config.hcl`):
```hcl
gossip {
  enabled = true
  port    = 7946

  # Required for token verification
  private_key_file = "/etc/agbero/gossip.key"

  # Optional: Seed nodes for clustering
  seeds = ["node2:7946", "node3:7946"]

  # Optional: Encrypt gossip traffic
  secret_key = "${env.GOSSIP_SECRET}"
}

# For HTTP discovery
discovery {
  enabled = true
  interval = "30s"
  endpoints = [
    "http://service1:8080/.well-known/agbero",
    "http://service2:8080/.well-known/agbero",
  ]
}
```

---

## Troubleshooting

### Common Issues:

1. **Services not discovered**:
   ```bash
   # Check if Agbero can reach the service
   curl http://service:8080/.well-known/agbero
   
   # Check gossip status
   agbero gossip status
   ```

2. **Token validation failed**:
   ```bash
   # Regenerate token
   agbero gossip token --service my-service --ttl 24h > token.txt
   ```

3. **Gossip nodes not connecting**:
   ```bash
   # Verify UDP port 7946 is open
   nc -z -u agbero-host 7946
   ```

### Monitoring:
```bash
# View discovered services
curl http://localhost:9090/metrics | jq '.services'

# Check gossip cluster membership
agbero gossip status

# Force service rediscovery
curl -X POST http://localhost:9090/discovery/refresh
```

---

## Security Considerations

1. **Token Management**: Rotate tokens regularly (recommended: 30 days)
2. **Network Security**: Restrict gossip traffic to trusted networks
3. **Encryption**: Use `secret_key` for encrypted gossip in production
4. **Validation**: Always validate tokens on the Agbero side

---

## Migration Guide

### From HTTP Discovery to Direct Gossip:
1. Add Memberlist dependency to your Go service
2. Generate a token with `agbero gossip token`
3. Update service to broadcast metadata via gossip
4. Test in staging before production

### From Direct Gossip to HTTP Discovery:
1. Add `/.well-known/agbero` endpoint to service
2. Remove Memberlist dependency
3. Update Agbero configuration to use HTTP discovery
4. Monitor for any service discovery delays
```

### 7. Rate Limiting with Multiple Strategies

**Problem**: Different endpoints need different rate limits.

**Solution**: Granular rate limiting:

```hcl
route "/public-api" {
  rate_limit {
    # Global rate limit for all users
    policy {
      requests = 100
      window   = "1m"
      burst    = 20
    }
    
    # Stricter limit for unauthenticated users
    policy {
      requests = 10
      window   = "1m"
      burst    = 5
      bucket   = "anonymous"
    }
    
    # Higher limit for API key holders
    policy {
      requests = 1000
      window   = "1m"
      burst    = 100
      key_header = "X-API-Key"
      bucket   = "api_key"
    }
  }
  
  backend {
    server {
      address = "http://api-service:8080"
    }
  }
}
```

### 8. TCP Proxy with SNI Routing

**Problem**: You need to proxy raw TCP connections (database, Redis, custom protocols).

**Solution**: Layer 4 TCP proxying:

```hcl
tcp {
  listen = ":5432"  # PostgreSQL default port

  route "*.db.internal" {
    strategy = "least_conn"

    backend {
      address = "postgres-primary:5432"
      weight  = 3
    }

    backend {
      address = "postgres-replica:5432"
      weight  = 1
    }
  }

  route "redis.internal" {
    strategy = "round_robin"

    backend {
      address = "redis-cluster:6379"
    }
  }
}
```

### 9. PHP Application with FastCGI

**Problem**: You need to serve a legacy PHP application alongside modern services.

**Solution**: Built-in PHP FastCGI support:

```hcl
route "/legacy-app" {
  web {
    root = "/var/www/php-app"

    php {
      enabled = true
      address = "unix:/var/run/php/php8.2-fpm.sock"
      index   = "index.php"
    }
  }
}
```

## 📊 Performance Comparison

| Feature | Agbero | Nginx | Caddy | Traefik |
|---------|---------|-------|-------|---------|
| **Zero-config local TLS** | ✅ Auto CA install | ❌ Manual | ⚠️ Requires mkcert | ❌ Manual |
| **Built-in Gossip** | ✅ Native | ❌ Requires Consul | ❌ Requires plugins | ❌ Requires plugins |
| **Weighted Load Balancing** | ✅ Native | ⚠️ Requires Nginx Plus | ✅ Basic | ✅ |
| **HTTP/3 by default** | ✅ | ❌ Experimental | ✅ | ✅ |
| **Latency Histograms** | ✅ HDR Histograms | ❌ Basic metrics | ❌ Basic metrics | ⚠️ With plugins |
| **Hot Reload** | ✅ File watching | ⚠️ With reload | ✅ | ✅ |
| **Memory Footprint** | ~15MB | ~5MB | ~10MB | ~25MB |

## 🔧 Advanced Configuration Patterns

### Blue-Green Deployment

```hcl
route "/" {
  # Use header-based routing for blue-green
  backend {
    strategy = "round_robin"

    # Blue environment (active)
    server {
      address = "http://blue-cluster:8080"
      conditions {
        headers = {
          "X-Env" = "blue"
        }
      }
    }

    # Green environment (staging)
    server {
      address = "http://green-cluster:8080"
      conditions {
        headers = {
          "X-Env" = "green"
        }
      }
    }

    # Default - send to blue
    server {
      address = "http://blue-cluster:8080"
    }
  }
}
```

### A/B Testing

```hcl
route "/checkout" {
  backend {
    strategy = "random"

    # Version A - 50% of traffic
    server {
      address = "http://checkout-v1:8080"
      weight  = 50
    }

    # Version B - 50% of traffic
    server {
      address = "http://checkout-v2:8080"
      weight  = 50
    }
  }

  # Track which version served the request
  headers {
    response {
      add = {
        "X-Backend-Version" = "${backend_version}"
      }
    }
  }
}
```

### Geo-Based Routing

```hcl
route "/cdn" {
  backend {
    # US East
    server {
      address = "http://us-east-cdn:8080"
      conditions {
        source_ips = ["us-east-ip-range/24"]
      }
    }

    # EU West
    server {
      address = "http://eu-west-cdn:8080"
      conditions {
        source_ips = ["eu-west-ip-range/24"]
      }
    }

    # Default fallback
    server {
      address = "http://global-cdn:8080"
    }
  }
}
```

### IP Restriction 

- Route Middleware (ip_allow): "Am I allowed to access this API Route at all?" (Gatekeeper).
- Backend Conditions: "Given I am allowed, which specific server inside the backend pool should I use?" (Routing logic).

```hcl
route "/api" {
   backend {
      # Who is allowed to use this backend
     allowed_ips = ["10.0.0.0/8"]
     server {
       address = "http://127.0.0.1:8080"
     }
   }
}
```

```hcl
route "/admin-area" {
  backend {
    server "http://127.0.0.1:8080" {
      conditions {
        # Acts as an Allow List. 
        # Access is denied for anyone NOT in this list.
        source_ips = ["127.0.0.1", "::1", "203.0.113.55"] 
      }
    }
  }
}
```

## 🚨 Common Issues & Solutions

### Issue: "Certificate not trusted" in browser
**Solution**: Run `agbero cert install-ca` to install the local CA to your system trust store.

### Issue: Gossip nodes not discovering each other
**Solution**:
1. Ensure UDP port 7946 is open between nodes
2. Verify tokens match with `agbero gossip status`
3. Check if nodes are in same network segment

### Issue: Rate limiting too aggressive
**Solution**: Use the `burst` parameter to allow temporary spikes:
```hcl
rate_limit {
  policy {
    requests = 100  # 100 requests per minute
    window   = "1m"
    burst    = 30   # Allow 30 immediate requests
  }
}
```

### Issue: Memory usage growing
**Solution**: Agbero uses bounded caches. Check:
1. Rate limit cache size (default 100k entries)
2. Forward auth cache (default 10k entries)
3. Route matching cache (default 10k entries)

## 🎯 Best Practices

1. **Separate configs**: Use `hosts.d/` directory with one file per service
2. **Use environment variables**: `${env.VAR_NAME}` in HCL for secrets
3. **Enable health checks**: Always configure health checks for production backends
4. **Set timeouts**: Always configure request timeouts for external services
5. **Monitor metrics**: Use the built-in `/metrics` endpoint
6. **Enable structured logging**: Especially in production with VictoriaLogs

## 🔗 Integration Examples

### Docker Compose

```yaml
version: '3.8'
services:
   agbero:
      image: your-registry/agbero:latest
      ports:
         - "80:80"
         - "443:443"
         - "7946:7946"  # Gossip port
      volumes:
         - ./config.hcl:/etc/agbero/config.hcl
         - ./hosts.d:/etc/agbero/hosts.d
         - agbero-data:/var/lib/agbero
      environment:
         - LETSENCRYPT_EMAIL=admin@example.com

   your-app:
      build: ..
      environment:
         - GOSSIP_TOKEN=${GOSSIP_TOKEN}
      healthcheck:
         test: [ "CMD", "curl", "-f", "http://localhost:8080/health" ]
         interval: 30s
         timeout: 5s
         retries: 3
```

### Kubernetes ConfigMap
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: agbero-config
data:
  config.hcl: |
    bind {
      https = [":443"]
    }

    hosts_dir = "/etc/agbero/hosts.d"

    gossip {
      enabled = true
      port = 7946
      private_key_file = "/etc/agbero/gossip.key"
    }

  app.hcl: |
    domains = ["app.example.com"]

    route "/" {
      backend {
        server {
          address = "http://app-service:8080"
        }
      }
    }
```