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
┌─────────┐     POST /api/v1/routes     ┌─────────┐
│ Service │─────────────────────────────►│ Agbero │
│   API   │                              │ Cluster│
└─────────┘                              └────┬────┘
│
┌──────────┼──────────┐
▼          ▼          ▼
┌─────────┐ ┌─────────┐ ┌─────────┐
│ Node 1  │ │ Node 2  │ │ Node 3  │
│ route   │ │ route   │ │ route   │
└─────────┘ └─────────┘ └─────────┘
```

1. A service (or orchestrator) calls the Agbero API
2. The route is stored in the cluster's gossip state
3. All nodes in the cluster receive the route automatically
4. Traffic is immediately load-balanced to the new service
5. Routes expire after TTL if not renewed

## Configuration

First, ensure the admin API is enabled in your `agbero.hcl`:

```hcl
admin {
  enabled = true
  address = ":9090"
  
  # Authentication for API access
  jwt_auth {
    enabled = true
    secret = "your-jwt-secret"  # or use internal_auth_key
  }
}
```

## Authentication

### Method 1: JWT Token (for automation)

```bash
# Get a JWT token
curl -X POST http://localhost:9090/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your-password"}'

# Response
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "expires": "2024-01-16T10:30:00Z"
}

# Use token for API calls
curl -X POST http://localhost:9090/api/v1/routes \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..." \
  -H "Content-Type: application/json" \
  -d '{
    "host": "service-123.example.com",
    "route": {
      "path": "/api/*",
      "backend": {
        "servers": [
          {"address": "http://10.0.0.123:8080", "weight": 1}
        ]
      }
    },
    "ttl_seconds": 300
  }'
```

### Method 2: Internal Auth Key (for service-to-service)

```bash
# Generate internal auth key (one-time setup)
agbero secret key init

# Generate a token for your service
agbero secret token --service auto-scaler --ttl 8760h

# Use token for API calls
curl -X POST http://localhost:9090/api/v1/routes \
  -H "Authorization: Bearer <token-from-command>" \
  -H "Content-Type: application/json" \
  -d '{
    "host": "service-123.example.com",
    "route": {
      "path": "/api/*",
      "backend": {
        "servers": [
          {"address": "http://10.0.0.123:8080", "weight": 1}
        ]
      }
    },
    "ttl_seconds": 300
  }'
```

## API Endpoints

### Create Ephemeral Route

**`POST /api/v1/routes`**

Creates a new route that is broadcast to all cluster nodes. The route will automatically expire after `ttl_seconds`.

**Request Body:**
```json
{
  "host": "service-123.example.com",
  "route": {
    "path": "/api/*",
    "backend": {
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
  "key": "route:service-123.example.com|/api/*"
}
```

**What happens:**
- Route is stored in cluster state with key `route:service-123.example.com|/api/*`
- All nodes receive the route within seconds
- Traffic to `service-123.example.com/api/*` is load-balanced to the specified backend
- After 300 seconds, the route is automatically deleted from all nodes

### Delete Ephemeral Route

**`DELETE /api/v1/routes`**

Explicitly remove a route before its TTL expires.

```bash
curl -X DELETE "http://localhost:9090/api/v1/routes?host=service-123.example.com&path=/api/*" \
  -H "Authorization: Bearer <token>"
```

**Response:**
```json
{
  "status": "deleted",
  "key": "route:service-123.example.com|/api/*"
}
```

## Real-World Usage Examples

### Example 1: Auto-scaling Web Service

When a new instance spins up in your auto-scaling group, it registers itself:

```python
import requests
import socket
import time

# Get my IP address
hostname = socket.gethostname()
ip_address = socket.gethostbyname(hostname)

# Register with Agbero
response = requests.post(
    "http://agbero-cluster:9090/api/v1/routes",
    headers={"Authorization": "Bearer your-token"},
    json={
        "host": f"webapp-{hostname}.example.com",
        "route": {
            "path": "/*",
            "backend": {
                "servers": [
                    {"address": f"http://{ip_address}:8080", "weight": 1}
                ]
            }
        },
        "ttl_seconds": 60  # Renew every minute
    }
)

# Keep renewing
while True:
    time.sleep(45)
    # Renew by POSTing again with same data
    requests.post(...)
```

### Example 2: Canary Deployment

Gradually shift traffic to a new version:

```bash
# Deploy v2 with 10% traffic
curl -X POST http://localhost:9090/api/v1/routes \
  -H "Authorization: Bearer <token>" \
  -d '{
    "host": "api.example.com",
    "route": {
      "path": "/v2/*",
      "backend": {
        "strategy": "round_robin",
        "servers": [
          {"address": "http://v1-api:8080", "weight": 90},
          {"address": "http://v2-api:8080", "weight": 10}
        ]
      }
    },
    "ttl_seconds": 3600
  }'

# After monitoring, shift to 50/50
curl -X POST http://localhost:9090/api/v1/routes \
  -H "Authorization: Bearer <token>" \
  -d '{
    "host": "api.example.com",
    "route": {
      "path": "/v2/*",
      "backend": {
        "strategy": "round_robin",
        "servers": [
          {"address": "http://v1-api:8080", "weight": 50},
          {"address": "http://v2-api:8080", "weight": 50}
        ]
      }
    },
    "ttl_seconds": 3600
  }'

# Finally, full v2
curl -X POST http://localhost:9090/api/v1/routes \
  -H "Authorization: Bearer <token>" \
  -d '{
    "host": "api.example.com",
    "route": {
      "path": "/v2/*",
      "backend": {
        "servers": [
          {"address": "http://v2-api:8080", "weight": 100}
        ]
      }
    },
    "ttl_seconds": 3600
  }'
```

### Example 3: Temporary Preview Environment

For each PR, create a temporary route:

```bash
#!/bin/bash
PR_NUMBER=$1
COMMIT_HASH=$2

# Deploy preview environment
kubectl apply -f k8s/preview-$PR_NUMBER.yaml

# Register with Agbero
curl -X POST http://agbero:9090/api/v1/routes \
  -H "Authorization: Bearer <token>" \
  -d "{
    \"host\": \"pr-$PR_NUMBER.preview.example.com\",
    \"route\": {
      \"path\": \"/*\",
      \"backend\": {
        \"servers\": [
          {\"address\": \"http://preview-$PR_NUMBER:8080\", \"weight\": 1}
        ]
      }
    },
    \"ttl_seconds\": 86400
  }"

echo "Preview URL: http://pr-$PR_NUMBER.preview.example.com"
```

### Example 4: Service Mesh Style Routing

Services discover and route to each other dynamically:

```go
package main

import (
    "bytes"
    "encoding/json"
    "net/http"
    "time"
)

type ServiceRegistry struct {
    apiURL    string
    token     string
    services  map[string]string
}

func (r *ServiceRegistry) Register(serviceName, address string, ttl int) error {
    route := map[string]interface{}{
        "host": serviceName + ".internal",
        "route": map[string]interface{}{
            "path": "/*",
            "backend": map[string]interface{}{
                "servers": []map[string]interface{}{
                    {"address": "http://" + address, "weight": 1},
                },
            },
        },
        "ttl_seconds": ttl,
    }
    
    data, _ := json.Marshal(route)
    resp, err := http.Post(
        r.apiURL+"/api/v1/routes",
        "application/json",
        bytes.NewReader(data),
    )
    return err
}

func (r *ServiceRegistry) Discover(serviceName string) (string, error) {
    // Routes are automatically available to all nodes
    // Just use the hostname: serviceName + ".internal"
    return serviceName + ".internal", nil
}

func main() {
    registry := &ServiceRegistry{
        apiURL: "http://agbero-cluster:9090",
        token:  "your-auth-token",
    }
    
    // Register this service
    registry.Register("auth-service", "10.0.0.50:9000", 30)
    
    // Discover and call another service
    authURL, _ := registry.Discover("auth-service")
    http.Get("http://" + authURL + "/health")
}
```

## Cluster Awareness

Routes created via the API are automatically distributed to all nodes in the cluster:

```bash
# On node1, create a route
curl -X POST http://node1:9090/api/v1/routes ... -d '{...}'

# On node2, the route is automatically available
curl http://node2:9090/uptime | jq '.hosts'
# The route appears in node2's configuration without any extra work
```

## Route Persistence vs Ephemeral Routes

| Feature | HCL Files (hosts.d/) | API Routes |
|---------|---------------------|------------|
| Persistence | Persistent on disk | Ephemeral, expires with TTL |
| Management | Manual file edits | Programmatic API |
| Distribution | File sync (manual/SCM) | Automatic cluster gossip |
| Use Case | Permanent services | Dynamic/temporary services |
| TTL Support | No | Yes |
| Auto-cleanup | No | Yes (on expiry) |

## Best Practices

1. **Use short TTLs with renewal** (30-60 seconds) for auto-scaling services
2. **Longer TTLs** (hours/days) for semi-permanent but dynamic routes
3. **Always authenticate** - use internal auth keys for service-to-service
4. **Monitor route counts** - ensure expired routes are being cleaned up
5. **Combine with HCL** - use HCL for infrastructure, API for application services

## Monitoring

Check active ephemeral routes via the uptime endpoint:

```bash
curl http://localhost:9090/uptime | jq '.hosts'

# Look for hosts with "route:" prefix in cluster metrics
curl http://localhost:9090/uptime | jq '.cluster.metrics'
```

## Next Steps

- **Cluster Setup**: See [Advanced Guide](./advance.md) for gossip configuration
- **Authentication**: See [Global Configuration](./global.md) for admin auth setup
- **Route Options**: See [Host Configuration](./host.md) for all route parameters