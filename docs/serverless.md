# Serverless Guide

No Lambda. No API Gateway. No tokens in the browser. No extra services to run.

## The Problem

Your frontend needs to call the Stripe API. The naive approach leaks your secret key to every browser that visits your site:

```javascript
// Every visitor can read this key in DevTools
const response = await fetch("https://api.stripe.com/v1/charges", {
  headers: { "Authorization": "Bearer sk_live_AbCdEf..." }
})
```

The standard fix is a backend service — a Node.js or Python app that proxies the call, injects the credential, and keeps the key server-side. That works, but now you have an extra service to deploy, monitor, restart when it crashes, and keep in sync with your frontend.

Agbero's `serverless` block is that proxy layer. Defined in HCL, no extra process, no extra deploy.

The same block also handles background workers, scheduled tasks, and on-demand script execution — things that would otherwise require PM2, cron, or a separate job runner.

## Two tools, one block

The `serverless` block inside any route gives you two primitives:

**`replay` blocks** proxy outbound HTTP calls to external APIs. Agbero injects your credentials, forwards the request, and streams the response back. Your API key stays on the server.

**`work` blocks** run local commands — on a schedule, as a persistent background daemon, triggered on-demand by an HTTP request, or once at startup.

Both live inside a `route` block and are reached by clients at predictable URL paths.

## REST Proxying

### How it works

```
Browser → POST /api/payments/stripe → Agbero injects Bearer token → api.stripe.com
```

The browser calls your Agbero route. Agbero resolves the credential from the server environment, adds it to the outbound request headers, calls the real API, and streams the response back. The secret never appears in a response, a log line visible to the client, or a network tab.

### Configuration

```hcl
route "/api/payments" {
  serverless {
    enabled = true

    replay "stripe" {
      enabled = true
      url     = "https://api.stripe.com/v1/charges"
      method  = "POST"
      timeout = "15s"

      headers = {
        "Authorization"  = "Bearer env.STRIPE_SECRET_KEY"
        "Stripe-Version" = "2024-04-10"
        "Content-Type"   = "application/json"
      }
    }
  }
}
```

Set the environment variable on your server:
```bash
export STRIPE_SECRET_KEY=sk_live_AbCdEf...
```

The browser calls `POST /api/payments/stripe` with its payload. Agbero calls Stripe with your key attached. Done.

Alternatively, store credentials in the keeper so they never appear in environment variables or config files at all:

```bash
# Store the key in the keeper
agbero keeper set integrations/stripe-key "sk_live_AbCdEf..."
```

```hcl
# Reference it in HCL using ss:// — resolved at request time, never logged
headers = {
  "Authorization" = "Bearer ss://integrations/stripe-key"
}
```

### URL structure

REST endpoints are always reachable at `{route-path}/{name}`:

```
POST /api/payments/stripe
GET  /api/data/github-search?q=agbero
GET  /api/data/weather?city=Lagos
```

### Forwarding query parameters from the client

```hcl
replay "github-search" {
  enabled       = true
  url           = "https://api.github.com/search/repositories"
  method        = "GET"
  forward_query = true   # pass incoming ?q=... directly to GitHub

  headers = {
    "Authorization" = "Bearer env.GITHUB_TOKEN"
    "Accept"        = "application/vnd.github+json"
  }
}
```

### Static query parameters (resolved server-side)

```hcl
replay "weather" {
  enabled       = true
  url           = "https://api.openweathermap.org/data/2.5/weather"
  method        = "GET"
  forward_query = true   # client sends ?city=Lagos, Agbero adds appid

  query = {
    "appid" = "env.OPENWEATHER_API_KEY"
    "units" = "metric"
  }
}
```

### Caching REST responses

Avoid hammering an upstream on repeated identical requests:

```hcl
replay "exchange-rates" {
  enabled = true
  url     = "https://api.exchangerate.host/latest"
  method  = "GET"

  headers = {
    "X-API-Key" = "env.EXCHANGE_KEY"
  }

  cache {
    enabled = true
    driver  = "memory"
    ttl     = "1h"
    methods = ["GET"]
    memory  { max_items = 100 }
  }
}
```

---

### Restricting outbound domains (`allowed_domains`)

When a `replay` block operates in relay mode — where the client supplies the target URL at request time via the `X-Agbero-Replay-Url` header or `?url=` query param — you **must** set `allowed_domains` to prevent SSRF attacks.

Without this, a malicious client could target internal services (Redis, metadata APIs, internal HTTP servers).

```hcl
replay "safe-relay" {
  enabled = true

  # Only these domains are allowed as relay targets
  allowed_domains = [
    "api.stripe.com",      # exact match
    "*.sendgrid.com",      # wildcard: matches mail.sendgrid.com, api.sendgrid.com, etc.
    "api.github.com",
  ]

  # Note: private IPs (10.x, 192.168.x, 127.x, etc.) are ALWAYS blocked
  # regardless of this list — it is a hard safety backstop
}
```

> Setting `allowed_domains = ["*"]` disables SSRF protection — **never use `"*"` in production**.

---

### Controlling response headers (`strip_headers`)

When relaying to an upstream that sets its own CORS or security headers, those headers can conflict with your application's policy. `strip_headers = true` removes them from the upstream response and adds permissive CORS headers instead:

```hcl
replay "cross-origin-api" {
  enabled       = true
  url           = "https://api.example.com/data"
  strip_headers = true  # removes upstream CSP, X-Frame-Options, etc.
                        # and sets Access-Control-Allow-Origin: <origin>
}
```

---

### Controlling the Referer header (`referer_mode`)

Controls what `Referer` header is sent to the upstream:

| Mode | Behaviour |
|------|-----------|
| `auto` *(default)* | Sets `Referer` to the target origin, e.g. `https://api.stripe.com/` |
| `fixed` | Uses the value in `referer_value` |
| `forward` | Passes the client's own `Referer` header through unchanged |
| `none` | Omits the `Referer` header entirely |

```hcl
replay "partner-api" {
  enabled       = true
  url           = "https://partner.example.com/api"
  referer_mode  = "fixed"
  referer_value = "https://myapp.example.com"  # always sends this as Referer
}
```

---

### Multiple REST endpoints on one route

```hcl
route "/integrations" {
  jwt_auth {
    enabled = true
    secret  = "env.JWT_SECRET"
  }

  serverless {
    enabled = true

    replay "stripe" {
      enabled = true
      url     = "https://api.stripe.com/v1/charges"
      method  = "POST"
      headers = { "Authorization" = "Bearer env.STRIPE_KEY" }
    }

    replay "sendgrid" {
      enabled = true
      url     = "https://api.sendgrid.com/v3/mail/send"
      method  = "POST"
      headers = {
        "Authorization" = "Bearer env.SENDGRID_KEY"
        "Content-Type"  = "application/json"
      }
    }

    replay "slack" {
      enabled = true
      url     = "https://hooks.slack.com/services/env.SLACK_WEBHOOK_PATH"
      method  = "POST"
      headers = { "Content-Type" = "application/json" }
    }
  }
}
```

## Workers

Workers are commands that Agbero manages for you. The same `work` block covers four execution modes depending on which fields you set.

### On-demand workers (HTTP-triggered)

When a client hits the worker endpoint, Agbero runs the command, pipes the request body to stdin, and streams stdout back as the HTTP response body. The process exits when the request completes.

```hcl
route "/tools" {
  serverless {
    enabled = true

    work "pdf" {
      command = ["/usr/local/bin/wkhtmltopdf", "--quiet", "-", "-"]
      timeout = "30s"
    }
  }
}
```

```bash
# Send HTML, receive PDF
curl -X POST https://myapp.com/tools/pdf \
  --data-binary @page.html \
  --output report.pdf
```

The HTML body arrives as stdin to `wkhtmltopdf`. The PDF streams out as the response. No temp files, no staging directory, no separate service.

Other use cases: image conversion with ImageMagick, data transformation with `jq`, running Python or Node scripts, shell pipelines.

Worker endpoints are reachable at `{route-path}/{name}`:
```
POST /tools/pdf
POST /tools/resize-image
POST /tools/convert-csv
```

### Background daemons

Processes that start when Agbero starts and keep running until Agbero stops. Agbero restarts them automatically if they exit.

```hcl
work "queue-consumer" {
  command    = ["python3", "consumer.py"]
  background = true
  restart    = "always"   # always | on-failure | never
  env = {
    REDIS_URL = "env.REDIS_URL"
    QUEUE     = "jobs"
  }
}
```

`restart = "always"` restarts on any exit, including clean ones. `restart = "on-failure"` only restarts on non-zero exit. `restart = "never"` runs once and stops.

Background workers do not expose an HTTP endpoint — they run outside the request cycle.

### Scheduled workers (cron)

```hcl
work "nightly-report" {
  command  = ["./scripts/generate-report.sh"]
  schedule = "0 2 * * *"   # 02:00 every day
  timeout  = "15m"
  env = {
    DATABASE_URL = "env.DATABASE_URL"
    REPORT_EMAIL = "ops@example.com"
  }
}
```

Standard five-field cron syntax: `minute hour day-of-month month day-of-week`.

### One-shot startup workers

Run exactly once when Agbero starts. Good for database migrations, cache warming, or any initialisation that must complete before traffic arrives.

```hcl
work "migrate" {
  command  = ["./bin/migrate", "up", "--yes"]
  run_once = true
  timeout  = "5m"
  env = {
    DATABASE_URL = "env.DATABASE_URL"
  }
}
```

## Environment Variables

Credentials and configuration are injected via the `env` map using the `env.` prefix to pull from the server environment at runtime. The value is resolved when the request arrives — never baked into the config file.

```hcl
work "reporter" {
  command = ["python3", "report.py"]
  env = {
    API_KEY      = "env.REPORT_API_KEY"
    DATABASE_URL = "env.DATABASE_URL"
    MODE         = "production"        # plain string also works
  }
}
```

### Scope and merge order

Environment variables are merged in this order, with later values winning:

1. Global env — defined at the top of `agbero.hcl` in the `env = { }` map
2. Route env — defined in `env = { }` inside the `route` block
3. Worker env — defined in `env = { }` inside the individual `work` or `replay` block

```hcl
# agbero.hcl
env = {
  LOG_LEVEL = "info"
  APP_ENV   = "production"
}
```

```hcl
# hosts.d/app.hcl
route "/api" {
  env = {
    LOG_LEVEL = "debug"       # overrides global for this route
  }

  serverless {
    enabled = true

    work "processor" {
      command = ["./processor"]
      env = {
        LOG_LEVEL = "warn"    # overrides route for this worker only
      }
    }
  }
}
```

## Working Directory

By default workers run from a directory under `work.d/` named after the host and worker. You can override this for the entire `serverless` block with `root`:

```hcl
serverless {
  enabled = true
  root    = "/opt/myapp"   # all workers and replay handlers run from here
}
```

When a route also has a `web.git` block, workers automatically resolve their working directory to the current Git deployment — so your worker always runs from the latest deployed code:

```hcl
route "/" {
  web {
    git {
      enabled = true
      id      = "myapp"
      url     = "https://github.com/org/myapp"
      branch  = "main"
    }
  }

  serverless {
    enabled = true

    work "warm-cache" {
      command  = ["npm", "run", "warm"]
      run_once = true           # runs once after each new deployment
    }
  }
}
```

## Complete Example

A realistic production setup: Stripe and SendGrid proxied without exposing keys, PDF generation on demand, a background job consumer, nightly cleanup, and a startup migration.

```hcl
# hosts.d/myapp.hcl
domains = ["myapp.example.com"]

tls {
  mode = "letsencrypt"
  letsencrypt { enabled = true; email = "ops@example.com" }
}

# Credential-injecting REST proxies — protected by JWT
route "/integrations" {
  jwt_auth {
    enabled = true
    secret  = "env.JWT_SECRET"
  }

  serverless {
    enabled = true

    replay "stripe-charge" {
      enabled = true
      url     = "https://api.stripe.com/v1/charges"
      method  = "POST"
      timeout = "20s"
      headers = {
        "Authorization"  = "Bearer env.STRIPE_SECRET_KEY"
        "Stripe-Version" = "2024-04-10"
        "Content-Type"   = "application/json"
      }
    }

    replay "send-email" {
      enabled = true
      url     = "https://api.sendgrid.com/v3/mail/send"
      method  = "POST"
      timeout = "10s"
      headers = {
        "Authorization" = "Bearer env.SENDGRID_API_KEY"
        "Content-Type"  = "application/json"
      }
    }
  }
}

# On-demand PDF generation — stdin HTML → stdout PDF
route "/export" {
  jwt_auth {
    enabled = true
    secret  = "env.JWT_SECRET"
  }

  serverless {
    enabled = true
    root    = "/opt/myapp"

    work "pdf" {
      command = ["node", "scripts/pdf.js"]
      timeout = "30s"
      env = {
        FONT_DIR = "/usr/share/fonts/myapp"
      }
    }
  }
}

# Background workers — internal only
route "/workers" {
  allowed_ips = ["127.0.0.1"]

  serverless {
    enabled = true
    root    = "/opt/myapp"

    work "job-consumer" {
      command    = ["./bin/consumer"]
      background = true
      restart    = "always"
      env = {
        REDIS_URL    = "env.REDIS_URL"
        DATABASE_URL = "env.DATABASE_URL"
        CONCURRENCY  = "4"
      }
    }

    work "cleanup" {
      command  = ["./scripts/cleanup.sh"]
      schedule = "0 3 * * *"
      timeout  = "30m"
      env = {
        DATABASE_URL = "env.DATABASE_URL"
        RETENTION    = "90d"
      }
    }

    work "migrate" {
      command  = ["./bin/migrate", "up", "--yes"]
      run_once = true
      timeout  = "5m"
      env = {
        DATABASE_URL = "env.DATABASE_URL"
      }
    }
  }
}

# Main app
route "/" {
  backend {
    server { address = "http://127.0.0.1:3000" }
  }
}
```

Frontend calls — zero credentials in the browser:

```javascript
// Stripe — key never in the browser
const charge = await fetch("/integrations/stripe-charge", {
  method: "POST",
  headers: {
    "Authorization": `Bearer ${userJWT}`,
    "Content-Type": "application/json"
  },
  body: JSON.stringify({ amount: 2000, currency: "usd", source: cardToken })
})

// Email — same pattern
await fetch("/integrations/send-email", {
  method: "POST",
  headers: { "Authorization": `Bearer ${userJWT}`, "Content-Type": "application/json" },
  body: JSON.stringify({ to: "user@example.com", subject: "Hello" })
})

// PDF — send HTML, receive PDF stream
const pdf = await fetch("/export/work/pdf", {
  method: "POST",
  headers: { "Authorization": `Bearer ${userJWT}` },
  body: document.documentElement.outerHTML
})
const blob = await pdf.blob()
const url = URL.createObjectURL(blob)
```

## Reference

### `replay` block fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | string (label) | Required. Used in the URL path: `/{name}` |
| `enabled` | Enabled | Enable this endpoint |
| `url` | string | Required. Target URL |
| `method` | string | HTTP method to use |
| `headers` | map[string]string | Static headers to add. Values support `env.VAR` and `ss://ns/key` for keeper secrets |
| `query` | map[string]Value | Static query parameters. Values support `env.VAR` and `ss://ns/key` |
| `forward_query` | bool | Pass incoming query parameters to the upstream |
| `timeout` | duration | Request timeout (default: 30s) |
| `cache` | Cache block | Cache upstream responses |
| `env` | map[string]Value | Environment variables for value resolution. Values support `env.VAR` and `ss://ns/key` |
| `allowed_domains` | []string | Allowed outbound domains in relay mode. Supports `*.domain.com` wildcards. Private/loopback IPs always blocked. Never use `"*"` in production. |
| `strip_headers` | Enabled | Strip upstream CORS/security headers from the response and re-add permissive CORS headers |
| `referer_mode` | string | `auto` (default — target origin), `fixed` (use `referer_value`), `forward` (pass client referer), `none` (omit Referer entirely) |
| `referer_value` | string | Fixed Referer value. Only used when `referer_mode = "fixed"` |

### `work` block fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | string (label) | Required. Used in URL path for on-demand workers: `/{name}` |
| `command` | []string | Required. Command and arguments |
| `background` | bool | Run as persistent background daemon |
| `restart` | string | Restart policy: `always`, `on-failure`, `never` |
| `run_once` | bool | Run exactly once at startup |
| `schedule` | string | Cron expression for periodic execution |
| `timeout` | duration | Maximum execution time |
| `env` | map[string]Value | Environment variables. Values support `env.VAR` and `ss://ns/key` for keeper secrets |
| `engine` | string | Runtime hint (informational only) |