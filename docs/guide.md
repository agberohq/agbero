# Agbero Guide: Practical Examples & Use Cases

Agbero uses HCL (HashiCorp Configuration Language) distributed across a global configuration file and individual host files. This guide walks you through common scenarios, from local development to production gateways.

## 1. Administration Basics

By default, the admin dashboard is available on port `9090`. It provides a visual overview of cluster health, routes, and active firewall bans.

### Enabling the Admin Dashboard

```hcl
# agbero.hcl
admin {
  enabled = true
  address = ":9090"
  
  basic_auth {
    enabled = true
    users   = ["admin:$2a$10$YourHashedPasswordHere"]
  }
}
```

### Changing the Admin Password

Agbero uses standard `bcrypt` hashing for passwords. You can generate a new hash using the built-in CLI tool:

```bash
agbero hash -p mynewpassword
# Output: $2a$10$wT0E.K...

# Update your agbero.hcl with the new hash and reload the server
agbero reload
```

## 2. Serving Local Files & PHP (The Basics)

Setting up a local web server with directory listings is incredibly simple. This is perfect for local development or serving static documentation.

```hcl
# hosts.d/local.hcl
domains = ["localhost"]

route "/" {
  web {
    root    = "~/"      # Serve from your home directory
    listing = true      # Enable directory browsing
    
    # Uncomment to enable PHP support (requires php-fpm running locally)
    # php {
    #   enabled = true
    #   address = "127.0.0.1:9000"
    #   index   = "index.php"
    # }
  }
}
```

## 3. Reverse Proxy & Path Rewriting

When fronting backend applications, you often need to manipulate the URL path before it reaches the upstream server. Agbero provides `strip_prefixes` and regex `rewrite` blocks.

```hcl
# hosts.d/api.hcl
domains = ["api.example.com"]

route "/api" {
  # 1. Remove '/api' from the path before forwarding
  strip_prefixes = ["/api"]
  
  # 2. Rewrite old v1 endpoints to a new internal structure
  rewrite {
    pattern = "^/v1/users/(.*)$"
    target  = "/users/$1?version=v1"
  }
  
  backend {
    strategy = "round_robin"
    server { address = "http://127.0.0.1:8081" }
    server { address = "http://127.0.0.1:8082" }
  }
}
```

## 4. Authentication Gateway

Agbero natively supports four authentication mechanisms at the edge. You can mix and match these to protect your internal services.

### Method A: Basic Authentication

```hcl
route "/private" {
  basic_auth {
    enabled = true
    realm   = "Restricted Area"
    users   =[
      "john:$2a$10$...",
      "jane:${env.JANE_HASH}"
    ]
  }
  backend { server { address = "http://localhost:3000" } }
}
```

### Method B: JWT Authentication

Validate a JSON Web Token, verify the issuer, and map claims into HTTP headers for your backend to consume.

```hcl
route "/dashboard" {
  jwt_auth {
    enabled = true
    secret  = "${env.JWT_SECRET}"
    issuer  = "auth.example.com"
    
    claim_map = {
      "sub"   = "X-User-ID"
      "email" = "X-User-Email"
    }
  }
  backend { server { address = "http://localhost:3000" } }
}
```

### Method C: OAuth2 / OIDC

Agbero handles the entire OAuth2 flow natively.

```hcl
route "/" {
  o_auth {
    enabled       = true
    provider      = "github"
    client_id     = "${env.GITHUB_CLIENT_ID}"
    client_secret = "${env.GITHUB_CLIENT_SECRET}"
    redirect_url  = "https://app.example.com/auth/callback"
    cookie_secret = "${env.OAUTH_COOKIE_SECRET}"
    email_domains = ["yourcompany.com"]
  }
  backend { server { address = "http://localhost:3000" } }
}
```

### Method D: Forward Authentication

Delegate authentication logic to an external service. Agbero pauses the request, calls your auth service, and either allows or blocks the request based on the HTTP status code.

```hcl
# hosts.d/forward.hcl
route "/secure" {
  forward_auth {
    enabled    = true
    url        = "http://auth-service:9000/verify"
    timeout    = "2s"
    on_failure = "deny"
    
    request {
      headers        = ["Authorization", "Cookie"]
      forward_method = true
      forward_uri    = true
      forward_ip     = true
    }
    
    response {
      # Pass these headers from the auth service down to your backend
      copy_headers =["X-User-Email", "X-User-Id"]
      cache_ttl    = "1m"
    }
  }
  backend { server { address = "http://localhost:3000" } }
}
```

#### Example: Writing a Forward Auth Server in Go

Here is a lightweight Go server that acts as the `auth-service` configured above.

```go
package main

import (
	"net/http"
	"strings"
)

// main initializes a simple forward authentication endpoint.
// It validates Bearer tokens and rejects unauthorized requests.
func main() {
	http.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		token := strings.TrimPrefix(auth, "Bearer ")

		if token == "super-secret-token" {
			// Success: Attach headers for Agbero to forward to the backend
			w.Header().Set("X-User-Email", "admin@example.com")
			w.Header().Set("X-User-Id", "101")
			w.WriteHeader(http.StatusOK)
			return
		}

		// Failure: Agbero will block the client request
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})

	http.ListenAndServe(":9000", nil)
}
```

## 5. Static Website with GitOps (Cook)

Agbero can directly pull your **pre-built** static site from Git and serve it with zero-downtime symlink swaps.

*Note: Agbero does not run Node.js or build tools. Configure your CI/CD pipeline to compile the app and push the `dist` folder to a dedicated deployment branch. Agbero will then pull that branch instantly.*

```hcl
# hosts.d/mysite.hcl
domains =["mysite.example.com"]

tls {
  mode  = "letsencrypt"
  email = "admin@example.com"
}

route "/" {
  web {
    index = "index.html"
    spa   = true
    
    git {
      enabled  = true
      id       = "mysite_frontend"
      url      = "https://github.com/org/repo.git"
      branch   = "deploy-branch" 
      sub_dir  = "dist"          
      interval = "5m"
    }
  }
}
```

## 6. Rate Limiting & Web Application Firewall

Protect your endpoints using global rate limit policies and Web Application Firewall (WAF) rules.

```hcl
# agbero.hcl (Global definitions)
rate_limits {
  enabled = true
  
  policy "api-tier" {
    requests = 100
    window   = "1m"
    burst    = 20
    key      = "ip"
  }
}

security {
  enabled = true
  firewall {
    enabled = true
    mode    = "active"
    
    rule "block-scanners" {
      type   = "static"
      action = "deny"
      match {
        any {
          location = "path"
          pattern  = "\\.env|wp-admin"
        }
      }
    }
  }
}
```

```hcl
# hosts.d/api.hcl (Applying the policy)
domains = ["api.example.com"]

route "/public" {
  rate_limit {
    enabled    = true
    use_policy = "api-tier"
  }
  
  backend {
    server { address = "http://api:8080" }
  }
}
```

## 7. TCP Proxy (Databases & Raw Sockets)

Agbero routes raw TCP traffic using SNI (Server Name Indication), allowing you to multiplex databases over a single port.

```hcl
# hosts.d/db.hcl
domains = ["db.internal"]

proxy "postgres" {
  enabled  = true
  listen   = ":5432"
  sni      = "*.db.internal"
  strategy = "least_conn"
  
  proxy_protocol = true
  
  backend {
    address = "tcp://postgres-1:5432"
    weight  = 1
  }
  
  backend {
    address = "tcp://postgres-2:5432"
    weight  = 1
  }
  
  health_check {
    enabled  = true
    interval = "10s"
    timeout  = "2s"
  }
}
```