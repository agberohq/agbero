# Agbero API Reference: Dynamic Route Management

The Agbero API allows you to create and manage routes dynamically without writing HCL files. Routes created via the API are ephemeral, can have time-to-live (TTL) values, and are automatically distributed across your entire cluster.

## Core Use Case: Dynamic Load Balancing

**Why use the API?**

Instead of manually creating HCL files for every new service deployment, you can programmatically add routes when services come online and remove them when they scale down. This is essential for:

- **Auto-scaling environments**: Services register themselves when they start
- **Temporary environments**: Preview deployments, test environments that auto-expire
- **Canary deployments**: Gradually shift traffic to new versions
- **Service mesh patterns**: Services discover and route to each other dynamically
- **Multi-tenant platforms**: Each tenant gets an ephemeral route with TTL

## How It Works

```
┌─────────┐     POST /auto/v1/route      ┌─────────┐
│ Service │─────────────────────────────►│ Agbero │
│   API   │                              │ Cluster│
└─────────┘                              └────┬────┘
│
┌─────────────────────┼─────────────────────┐
▼                     ▼                     ▼
┌─────────┐           ┌─────────┐           ┌─────────┐
│ Node 1  │           │ Node 2  │           │ Node 3  │
│ route   │           │ route   │           │ route   │
└─────────┘           └─────────┘           └─────────┘
```

1. A service (or orchestrator) calls the Agbero API
2. The route is stored in the cluster's gossip state with key `route:host|path`
3. All nodes in the cluster receive the route automatically via gossip
4. Traffic is immediately load-balanced to the new service
5. Routes expire after TTL if not renewed

---

## Prerequisites

### 1. Enable Admin API

First, ensure the admin API is enabled in your `agbero.hcl`:

```hcl
admin {
  enabled = true
  address = ":9090"  # bind address for the admin/API server
}
```

### 2. Generate the Internal Auth Key (one-time setup)

The `/auto/v1/` endpoints require an Ed25519 internal auth key stored in the keeper.
Without this key, the auto API is silently disabled and requests return 404.

```bash
# Generate and store the master Ed25519 key in the keeper
agbero secret key init
```

### 3. Generate a Service Token

```bash
# Generate a signed token for your service
agbero secret token --service auto-scaler --ttl 8760h

# The output shows the token and its JTI:
# API Token for service: auto-scaler
# JTI: abc123def456          ← keep this — needed for revocation
# Expires: 2025-03-15T10:30:00Z (8760h0m0s)
# eyJhbGciOiJFZERTQSIs...   ← use this as Bearer token
```

> **Service scope rule:** A token for service `"myapp"` can only register routes for hosts
> that start with `myapp-` or `myapp.` — e.g. `myapp-123.internal` or `myapp.example.com`.
> This prevents one service from hijacking another service's routes.

### 4. Get an Admin Token (for the `/api/v1/` endpoints)

```bash
# Login to get an admin JWT (8-hour session)
curl -X POST http://localhost:9090/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your-password"}'

# Response
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "expires": "2024-01-16T10:30:00Z"
}
```

---

## API Endpoints

All API endpoints are under the `/auto/v1/` prefix and require authentication.

### Base URL

```
http://localhost:9090/auto/v1/
```

### Authentication Header

All requests must include an `Authorization` header:

```bash
# JWT token
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...

# Internal auth token
Authorization: Bearer eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...
```

---

### Ping

**`GET /auto/v1/ping`**

Check that the API is reachable and your token is valid. Returns the service name from the token.

```bash
curl http://localhost:9090/auto/v1/ping \
  -H "Authorization: Bearer <your-token>"

# Response
{
  "status": "ok",
  "service": "auto-scaler"
}
```

---

### Create Ephemeral Route

**`POST /auto/v1/route`**

Creates a new route that is broadcast to all cluster nodes. The route will automatically expire after `ttl_seconds`.

**Request Body:**
```json
{
  "host": "service-123.example.com",
  "route": {
    "path": "/auto/*",
    "backend": {
      "strategy": "round_robin",
      "servers": [
        {
          "address": "http://10.0.0.123:8080",
          "weight": 1
        }
      ]
    }
  },
  "ttl_seconds": 300
}
```

**Response:**
```json
{
  "status": "ok",
  "key": "route:service-123.example.com|/auto/*"
}
```

**What happens:**
- Route is stored in cluster gossip state with key `route:service-123.example.com|/auto/*`
- All nodes in the cluster receive the route within seconds automatically
- Traffic to `service-123.example.com/auto/*` is immediately load-balanced to the specified backend
- After 300 seconds, the route is automatically removed from all nodes — no cleanup needed

**Supported route fields:**
| Field | Description | Example |
|-------|-------------|---------|
| `path` | Route path pattern | `/auto/*`, `/users/{id}` |
| `backend.strategy` | Load balancing strategy | `round_robin`, `least_conn`, `ip_hash` |
| `backend.servers[].address` | Backend server address | `http://10.0.0.123:8080` |
| `backend.servers[].weight` | Server weight (for weighted strategies) | `1` (default), `10` |

---

### Delete Ephemeral Route

**`DELETE /auto/v1/route`**

Explicitly remove a route before its TTL expires.

**Query Parameters:**
| Parameter | Description | Required |
|-----------|-------------|----------|
| `host` | Hostname of the route | Yes |
| `path` | Path of the route (default: `/`) | No |

**Request:**
```bash
curl -X DELETE "http://localhost:9090/auto/v1/route?host=service-123.example.com&path=/auto/*" \
  -H "Authorization: Bearer <token>"
```

**Response:**
```json
{
  "status": "deleted",
  "key": "route:service-123.example.com|/auto/*"
}
```

---

## Route Storage Format

Routes created via the API are stored in the cluster with a wrapper that includes expiration metadata:

```go
type ClusterRouteWrapper struct {
Route     alaye.Route `json:"route"`
ExpiresAt time.Time   `json:"expires_at"`
}
```

The cluster key format is:
```
route:{host}|{path}
```

Example: `route:service-123.example.com|/auto/*`

---

## Revoking a Service Token

If a token is compromised or a service is decommissioned, revoke it immediately so it stops working even before it expires.

**`POST /api/v1/auto/revoke`**

This endpoint requires an **admin token** (from `POST /login`), not a service token.

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `jti` | string | Yes | The JTI shown when the token was generated |
| `service` | string | No | Service name (for audit log) |
| `expires_at` | RFC3339 | Yes | The token's expiry time (shown at generation) |

```bash
curl -X POST http://localhost:9090/api/v1/auto/revoke \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "jti": "abc123def456",
    "service": "auto-scaler",
    "expires_at": "2025-03-15T10:30:00Z"
  }'

# Response
{
  "status": "ok",
  "jti": "abc123def456"
}
```

> **Notes:**
> - `expires_at` must be in the future. If the token is already expired, the call returns `200 ok` with a "already expired" message — no action needed.
> - `expires_at` is capped at 400 days from now to prevent the revocation store from growing indefinitely.
> - Revocation is checked on every request to `/auto/v1/` endpoints.

---

## Real-World Usage Examples

### Example 1: Auto-scaling Web Service (Python)

When a new instance spins up in your auto-scaling group, it registers itself:

```python
import requests
import socket
import time
import os

# Configuration
API_URL = "http://agbero-cluster:9090/auto/v1"
TOKEN = os.environ.get("AGBERO_TOKEN")

class ServiceRegistry:
    def __init__(self, service_name, port):
        self.service_name = service_name
        self.port = port
        self.hostname = socket.gethostname()
        self.ip_address = socket.gethostbyname(self.hostname)

    def register(self, ttl=60):
        """Register this service with Agbero"""
        payload = {
            "host": f"{self.service_name}-{self.hostname}.internal",
            "route": {
                "path": "/*",
                "backend": {
                    "servers": [
                        {
                            "address": f"http://{self.ip_address}:{self.port}",
                            "weight": 1
                        }
                    ]
                }
            },
            "ttl_seconds": ttl
        }

        response = requests.post(
            f"{API_URL}/routes",
            headers={"Authorization": f"Bearer {TOKEN}"},
            json=payload
        )

        if response.status_code == 200:
            print(f"Registered {self.service_name} with TTL {ttl}s")
            return response.json()["key"]
        else:
            print(f"Registration failed: {response.text}")
            return None

    def heartbeat(self, key, ttl=60):
        """Renew registration by re-POSTing"""
        return self.register(ttl)

# Usage
if __name__ == "__main__":
    registry = ServiceRegistry("webapp", 8080)

    # Initial registration
    key = registry.register(ttl=30)

    # Heartbeat loop
    while True:
        time.sleep(25)
        registry.heartbeat(key, ttl=30)
```

---

### Example 2: Canary Deployment (Bash)

Gradually shift traffic to a new version:

```bash
#!/bin/bash
API="http://localhost:9090/auto/v1"
TOKEN="your-token-here"

# Deploy v2 with 10% traffic
curl -X POST "$API/routes" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "host": "api.example.com",
    "route": {
      "path": "/*",
      "backend": {
        "strategy": "weighted_least_conn",
        "servers": [
          {"address": "http://v1-api:8080", "weight": 90},
          {"address": "http://v2-api:8080", "weight": 10}
        ]
      }
    },
    "ttl_seconds": 3600
  }'

# After monitoring, shift to 50/50
curl -X POST "$API/routes" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "host": "api.example.com",
    "route": {
      "path": "/*",
      "backend": {
        "servers": [
          {"address": "http://v1-api:8080", "weight": 50},
          {"address": "http://v2-api:8080", "weight": 50}
        ]
      }
    },
    "ttl_seconds": 3600
  }'

# Finally, full v2
curl -X POST "$API/routes" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "host": "api.example.com",
    "route": {
      "path": "/*",
      "backend": {
        "servers": [
          {"address": "http://v2-api:8080", "weight": 100}
        ]
      }
    },
    "ttl_seconds": 3600
  }'
```

---

### Example 3: Temporary Preview Environment (Go)

For each PR, create a temporary route:

```go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

type RouteRequest struct {
	Host       string      `json:"host"`
	Route      RouteConfig `json:"route"`
	TTLSeconds int         `json:"ttl_seconds"`
}

type RouteConfig struct {
	Path    string        `json:"path"`
	Backend BackendConfig `json:"backend"`
}

type BackendConfig struct {
	Servers []ServerConfig `json:"servers"`
}

type ServerConfig struct {
	Address string `json:"address"`
	Weight  int    `json:"weight,omitempty"`
}

func createPreviewRoute(prNumber, commitHash string) error {
	apiURL := os.Getenv("AGBERO_API_URL")
	token := os.Getenv("AGBERO_TOKEN")

	route := RouteRequest{
		Host: fmt.Sprintf("pr-%s.preview.example.com", prNumber),
		Route: RouteConfig{
			Path: "/*",
			Backend: BackendConfig{
				Servers: []ServerConfig{
					{
						Address: fmt.Sprintf("http://preview-%s:8080", prNumber),
						Weight:  1,
					},
				},
			},
		},
		TTLSeconds: 86400, // 24 hours
	}

	data, _ := json.Marshal(route)
	req, _ := http.NewRequest("POST", apiURL+"/routes", bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API returned %d", resp.StatusCode)
	}

	fmt.Printf("Preview URL: http://pr-%s.preview.example.com\n", prNumber)
	return nil
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: create-preview <pr-number> <commit-hash>")
		os.Exit(1)
	}

	if err := createPreviewRoute(os.Args[1], os.Args[2]); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}
```

---

### Example 4: Service Mesh Style Routing (Node.js)

Services discover and route to each other dynamically:

```javascript
// service-registry.js
const axios = require('axios');

class ServiceRegistry {
    constructor(apiUrl, token) {
        this.apiUrl = apiUrl;
        this.token = token;
        this.services = new Map();
    }

    async register(serviceName, address, port, ttl = 30) {
        const hostname = require('os').hostname();
        const payload = {
            host: `${serviceName}-${hostname}.internal`,
            route: {
                path: '/*',
                backend: {
                    servers: [
                        { address: `http://${address}:${port}`, weight: 1 }
                    ]
                }
            },
            ttl_seconds: ttl
        };

        try {
            const response = await axios.post(
                `${this.apiUrl}/routes`,
                payload,
                { headers: { Authorization: `Bearer ${this.token}` } }
            );

            console.log(`Registered ${serviceName} with TTL ${ttl}s`);
            return response.data.key;
        } catch (error) {
            console.error('Registration failed:', error.message);
            return null;
        }
    }

    async discover(serviceName) {
        // Routes are automatically available to all nodes
        // Just use the hostname pattern: serviceName-instance.internal
        return `${serviceName}-*.internal`;
    }

    async call(serviceName, path) {
        // In real code, you'd need to get actual instance IPs
        // This is a simplified example
        const hostPattern = await this.discover(serviceName);
        // In practice, you'd query the cluster or use DNS
        return `http://${hostPattern.replace('*', 'active')}${path}`;
    }
}

// Usage
async function main() {
    const registry = new ServiceRegistry(
        'http://agbero-cluster:9090/auto/v1',
        process.env.AGBERO_TOKEN
    );

    // Register this service
    await registry.register('auth-service', '10.0.0.50', 9000, 30);

    // Discover and call another service
    const authURL = await registry.call('auth-service', '/health');
    console.log(`Auth service URL: ${authURL}`);
}

main();
```

---

## Monitoring Routes

### Check Active Routes via Uptime Endpoint

```bash
curl http://localhost:9090/uptime | jq '.hosts'
```

Look for hosts with dynamic routes (they'll appear like regular hosts).

### Cluster Metrics

```bash
curl http://localhost:9090/uptime | jq '.cluster.metrics'
```

Example response:
```json
{
  "updates_received": 150,
  "updates_ignored": 12,
  "deletes": 45,
  "joins": 3,
  "leaves": 1
}
```

---

## Route Persistence vs Ephemeral Routes

| Feature | HCL Files (`hosts.d/`) | API Routes |
|---------|------------------------|------------|
| **Persistence** | Persistent on disk | Ephemeral, expires with TTL |
| **Management** | Manual file edits | Programmatic API |
| **Distribution** | File sync (manual/SCM) | Automatic cluster gossip |
| **Use Case** | Permanent services | Dynamic/temporary services |
| **TTL Support** | No | Yes |
| **Auto-cleanup** | No | Yes (on expiry) |
| **Key Format** | Filename-based | `route:{host}\|{path}` |

---

## Best Practices

1. **Use short TTLs with renewal** (30-60 seconds) for auto-scaling services
2. **Longer TTLs** (hours/days) for semi-permanent but dynamic routes
3. **Always authenticate** - use internal auth keys for service-to-service
4. **Monitor route counts** - ensure expired routes are being cleaned up
5. **Combine with HCL** - use HCL for infrastructure, API for application services
6. **Include health checks** in your service registration
7. **Implement graceful shutdown** - deregister on service termination

### Renewal Pattern

```python
def run_with_registration(registry, ttl=30):
    key = registry.register(ttl)
    try:
        while True:
            time.sleep(ttl * 0.8)  # Renew at 80% of TTL
            registry.heartbeat(key, ttl)
    except KeyboardInterrupt:
        # Optionally deregister on shutdown
        registry.deregister(key)
```

---

## Error Handling

| HTTP Status | Meaning | Handling |
|-------------|---------|----------|
| `200 OK` | Success | Proceed |
| `400 Bad Request` | Invalid JSON or missing fields | Check request format |
| `401 Unauthorized` | Missing or invalid token | Check authentication |
| `403 Forbidden` | Token invalid or expired | Refresh token |
| `500 Internal Server Error` | Server error | Retry with backoff |
| `503 Service Unavailable` | Cluster disabled | Enable gossip cluster |

---

## Rate Limiting

The API itself is subject to rate limiting if configured in `rate_limits`. Consider excluding the API from rate limits:

```hcl
rate_limits {
  rules = [
    {
      name = "global-limit"
      prefixes = ["/auto/"]
      enabled = false  # Disable rate limiting for API
    }
  ]
}
```

---

## Implementation Details

The API is implemented in:

- `internal/operation/api/auto.go` - Route and ping handlers
- `internal/operation/api/revoke.go` - Token revocation handler
- `internal/operation/api/api.go` - Router registration
- `admin.go` - Admin server setup and authentication

### Key Components

```go
// Route storage in cluster
type ClusterRouteWrapper struct {
Route     alaye.Route `json:"route"`
ExpiresAt time.Time   `json:"expires_at"`
}

// API request payload
type routePayload struct {
Host       string      `json:"host"`
Route      alaye.Route `json:"route"`
TTLSeconds int         `json:"ttl_seconds"`
}
```

---

## Next Steps

- **Cluster Setup**: See [Advanced Guide](./advance.md) for gossip configuration
- **Authentication**: See [Global Configuration](./global.md) for admin auth setup
- **Route Options**: See [Host Configuration](./host.md) for all route parameters
- **CLI Reference**: See [Command Guide](./command.md) for generating tokens