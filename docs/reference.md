# Configuration Reference

Agbero uses [HCL](https://github.com/hashicorp/hcl) (HashiCorp Configuration Language) for all configuration. HCL is human-readable, supports comments, and allows expressions including environment variable interpolation.

The main configuration file is typically named `agbero.hcl`. Host-specific configurations are separate files placed in the `hosts_dir`.

---

## Value Interpolation

Any `Value`-typed field supports three resolution forms:

| Form | Example | Resolves to |
|------|---------|-------------|
| Plain string | `"hello"` | The literal string `"hello"` |
| Environment variable | `"env.MY_VAR"` | The value of `$MY_VAR` at runtime |
| Keeper secret | `"ss://namespace/key"` | The secret stored in the keeper under `namespace/key` |

```hcl
# All three forms work anywhere a Value is accepted
headers = {
  "X-Static"  = "my-fixed-value"              # plain string
  "X-Env"     = "env.API_KEY"                 # from environment
  "X-Secret"  = "ss://integrations/api-key"   # from keeper
}
```

> **Backwards compatibility:** The legacy `env:VAR` form (colon syntax) is also accepted.

If an environment variable is not set, the literal string is used as-is. If a keeper secret key does not exist, the raw `ss://` reference is used and a warning is logged.

---

## Global Configuration (`agbero.hcl`)

### Top-level fields

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `version` | `int` | `version` | Config file version. Currently `1`. |
| `development` | `bool` | `development` | Enable development/debug mode. |
| `env` | `map[string]Value` | `env` | Global environment variable map. |

### `bind` block

Controls which ports Agbero listens on.

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `http` | `[]string` | `http` | HTTP bind addresses, e.g. `[":80", "0.0.0.0:8080"]` |
| `https` | `[]string` | `https` | HTTPS bind addresses, e.g. `[":443"]` |
| `redirect` | `Enabled` | `redirect` | Auto-redirect HTTP → HTTPS when both are configured |

At least one of `http` or `https` must be provided.

### `timeouts` block

Global default timeouts (can be overridden per-route).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `read` | `duration` | `10s` | Max time to read the request |
| `write` | `duration` | `30s` | Max time to write the response |
| `idle` | `duration` | `120s` | Keep-alive idle timeout |
| `read_header` | `duration` | `5s` | Max time to read request headers |

### `general` block

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_header_bytes` | `int` | `1048576` (1 MB) | Maximum size of HTTP request headers |

### `storage` block

| Field | Type | Description |
|-------|------|-------------|
| `hosts_dir` | `string` | Directory containing host config files |
| `certs_dir` | `string` | Directory for certificate storage |
| `data_dir` | `string` | Directory for runtime data (keeper.db, firewall.db, telemetry store, revocation store, etc.) |
| `work_dir` | `string` | Working directory for workers and git repos |

### `admin` block

See [Admin](#admin-block).

### `api` block

Internal API configuration (used by the admin UI and management endpoints).

### `logging` block

See [Logging](#logging-block).

### `security` block

See [Security](#security-block).

### `rate_limits` block

See [Rate Limiting](#rate_limits-block).

### `gossip` block

See [Gossip / Clustering](#gossip-block).

### `letsencrypt` block

Global Let's Encrypt defaults.

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `Enabled` | Enable Let's Encrypt |
| `email` | `string` | ACME account email |
| `staging` | `bool` | Use Let's Encrypt staging environment |
| `short_lived` | `bool` | Request short-lived certificates |

### `fallback` block

Global fallback response for unmatched requests. See [Fallback](#fallback-block).

### `error_pages` block

Global custom error pages. See [ErrorPages](#error_pages-block).

---

## Host Configuration

Each host is a separate `.hcl` file in `hosts_dir`. The file may contain multiple `route` and `proxy` blocks.

### `Host` fields

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `domains` | `[]string` | `domains` | **Required.** Domain names this host responds to. Supports wildcards (`*.example.com`). |
| `bind` | `[]string` | `bind` | Specific ports this host binds to (overrides global). |
| `not_found_page` | `string` | `not_found_page` | Path to custom 404 page. |
| `compression` | `bool` | `compression` | Enable gzip compression globally for this host. |
| `tls` | `TLS` | `tls` block | TLS configuration. |
| `limits` | `Limit` | `limits` block | Host-level request limits. |
| `headers` | `Headers` | `headers` block | Headers to inject on all routes. |
| `error_pages` | `ErrorPages` | `error_pages` block | Custom error pages for this host. |
| `routes` | `[]Route` | `route` blocks | HTTP route handlers. **At least one required.** |
| `proxies` | `[]Proxy` | `proxy` blocks | TCP proxy listeners. |

---

## `route` block

Routes match incoming HTTP requests by path prefix. The `path` is a label (positional).

```hcl
route "/api/v1" {
  # ...
}
```

### Route fields

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `enabled` | `Enabled` | `enabled` | Enable/disable this route |
| `path` | `string` | *(label)* | **Required.** Path prefix. Must start with `/`. |
| `env` | `map[string]Value` | `env` | Route-scoped env vars |
| `strip_prefixes` | `[]string` | `strip_prefixes` | Path prefixes to strip before proxying |
| `allowed_ips` | `[]string` | `allowed_ips` | Restrict access to these IPs/CIDRs |
| `rewrites` | `[]Rewrite` | `rewrite` blocks | URL rewrite rules |

**Exactly one** of the following engine blocks must be set:

| Block | Description |
|-------|-------------|
| `web` | Serve static files |
| `backend` | Reverse proxy to upstream servers |
| `serverless` | Execute local functions/workers |

### Auth blocks (any route)

| Block | Description |
|-------|-------------|
| `basic_auth` | HTTP Basic Authentication |
| `forward_auth` | Delegate auth to external service |
| `jwt_auth` | JWT Bearer token validation |
| `o_auth` | OAuth 2.0 / OIDC |

### Middleware blocks (any route)

| Block | Description |
|-------|-------------|
| `headers` | Inject/remove request and response headers |
| `cors` | Cross-Origin Resource Sharing |
| `cache` | Response caching |
| `rate_limit` | Per-route rate limiting |
| `compression` | Response compression |
| `wasm` | WebAssembly middleware |
| `rewrite` | URL path rewrites |
| `firewall` | Per-route firewall rules |
| `error_pages` | Custom error pages |
| `fallback` | Fallback responses |
| `timeouts` | Per-route timeout overrides |
| `health_check` | Upstream health checks (proxy routes only) |
| `circuit_breaker` | Circuit breaker (proxy routes only) |

---

## `backend` block

Configures reverse proxy backends.

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `enabled` | `Enabled` | `enabled` | Enable this backend config |
| `strategy` | `string` | `strategy` | Load balancing strategy (see below) |
| `keys` | `[]string` | `keys` | Custom hash keys for consistent/hash strategies |
| `servers` | `[]Server` | `server` blocks | Upstream backend servers |

**Strategies:** `round_robin` (default), `random`, `least_conn`, `weighted_least_conn`, `ip_hash`, `url_hash`, `least_response_time`, `power_of_two`, `consistent_hash`, `adaptive`, `sticky`.

### `server` block (inside `backend`)

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `address` | `Address` | *(attr)* | **Required.** Backend address. Schemes: `http://`, `https://`, `tcp://`. |
| `weight` | `int` | `weight` | Relative weight (default: `1`) |
| `max_connections` | `int64` | `max_connections` | Maximum concurrent connections to this server |
| `criteria` | `Criteria` | `criteria` block | Routing criteria for selective targeting |
| `streaming` | `Streaming` | `streaming` block | HTTP streaming configuration |

### `criteria` block

| Field | Type | Description |
|-------|------|-------------|
| `source_ips` | `[]string` | Only route to this server from these IPs/CIDRs |
| `headers` | `map[string]string` | Only route to this server when these headers match |

### `streaming` block

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `Enabled` | — | Enable streaming mode |
| `flush_interval` | `duration` | `100ms` | How often to flush buffered data |

---

## `web` block

Serves static files from a local directory or Git repository.

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `enabled` | `Enabled` | `enabled` | Enable web serving |
| `root` | `WebRoot` | `root` | **Required** (unless `git` is enabled). Root directory path. |
| `index` | `[]string` | `index` | Index filenames to look up (default: `["index.html"]`) |
| `listing` | `bool` | `listing` | Enable directory listing |
| `spa` | `bool` | `spa` | SPA mode: fall back to `index.html` for unmatched paths |
| `php` | `PHP` | `php` block | PHP-FPM integration |
| `git` | `Git` | `git` block | Git repository source |
| `markdown` | `Markdown` | `markdown` block | Markdown rendering |

### `git` block

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `enabled` | `Enabled` | `enabled` | Enable Git source |
| `id` | `string` | `id` | **Required.** Unique identifier for this git source |
| `url` | `string` | `url` | **Required.** Repository URL |
| `branch` | `string` | `branch` | Branch to clone (default: repo default) |
| `secret` | `Value` | `secret` | Webhook secret for push events |
| `interval` | `Duration` | `interval` | Polling interval for updates |
| `work_dir` | `string` | `work_dir` | Local directory for git checkout |
| `sub_dir` | `string` | `sub_dir` | Subdirectory within the repo to serve |
| `auth` | `GitAuth` | `auth` block | Repository authentication |

### `git.auth` block

| Field | Type | Description |
|-------|------|-------------|
| `type` | `string` | Auth type: `basic`, `ssh-key`, `ssh-agent` |
| `username` | `string` | Username for basic auth |
| `password` | `Value` | Password or token |
| `ssh_key` | `Value` | SSH private key (PEM format) |
| `ssh_key_passphrase` | `Value` | Passphrase for encrypted SSH key |

### `markdown` block

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `enabled` | `Enabled` | `enabled` | Enable markdown rendering |
| `unsafe` | `Enabled` | `unsafe` | Allow raw HTML in markdown |
| `toc` | `Enabled` | `toc` | Generate table of contents |
| `extensions` | `[]string` | `extensions` | Goldmark extensions |
| `template` | `string` | `template` | Custom HTML template path |
| `view` | `string` | `view` | Set to `"browse"` to enable directory browse mode |
| `highlight` | `Highlight` | `highlight` block | Code syntax highlighting |

### `php` block

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `enabled` | `Enabled` | `enabled` | Enable PHP-FPM |
| `address` | `string` | `address` | PHP-FPM address: `host:port` or `unix:/path/to/sock` |

---

## `serverless` block

Runs local functions as HTTP endpoints or background workers.

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `enabled` | `Enabled` | `enabled` | Enable serverless mode |
| `root` | `string` | `root` | Root directory for function files |
| `replays` | `[]Replay` | `replay` blocks | Outbound HTTP proxy endpoint definitions |
| `workers` | `[]Work` | `work` blocks | Background worker definitions |

### `replay` block (inside `serverless`)

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `name` | `string` | *(label)* | **Required.** Endpoint name. Reachable at `{route-path}/{name}` |
| `enabled` | `Enabled` | `enabled` | Enable this endpoint |
| `url` | `string` | `url` | **Required.** Target URL |
| `method` | `string` | `method` | HTTP method |
| `headers` | `map[string]string` | `headers` | Static request headers. Values support `env.VAR` and `ss://ns/key` for keeper secrets |
| `query` | `map[string]Value` | `query` | Static query parameters. Values support `env.VAR` and `ss://ns/key` |
| `forward_query` | `bool` | `forward_query` | Forward incoming query params to the upstream |
| `timeout` | `Duration` | `timeout` | Request timeout (default: `30s`) |
| `cache` | `Cache` | `cache` block | Cache upstream responses |
| `env` | `map[string]Value` | `env` | Environment variables for value resolution |
| `allowed_domains` | `[]string` | `allowed_domains` | Allowed outbound domains in relay mode. Supports `*.domain.com` wildcards. Private/loopback IPs always blocked. Never use `"*"` in production. |
| `strip_headers` | `Enabled` | `strip_headers` | Strip upstream CORS and security headers, re-add permissive CORS |
| `referer_mode` | `string` | `referer_mode` | `auto` (default — target origin), `fixed` (use `referer_value`), `forward` (pass client referer), `none` (omit) |
| `referer_value` | `string` | `referer_value` | Fixed Referer value used when `referer_mode = "fixed"` |

### `work` block (inside `serverless`)

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `name` | `string` | *(label)* | **Required.** Worker name |
| `engine` | `string` | `engine` | Runtime hint |
| `command` | `[]string` | `command` | **Required.** Command and arguments |
| `env` | `map[string]Value` | `env` | Environment variables |
| `background` | `bool` | `background` | Run as background process |
| `restart` | `string` | `restart` | Restart policy: `always`, `on-failure`, `never` |
| `run_once` | `bool` | `run_once` | Execute exactly once at startup |
| `schedule` | `string` | `schedule` | Cron schedule expression |
| `timeout` | `Duration` | `timeout` | Execution timeout |
| `cache` | `Cache` | `cache` block | Result caching |

---

## `proxy` block (TCP/L4)

Defines a TCP proxy listener on the host.

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `enabled` | `Enabled` | `enabled` | Enable this proxy |
| `name` | `string` | *(label)* | **Required.** Proxy name |
| `listen` | `string` | `listen` | **Required.** Listen address (e.g. `:5432`) |
| `sni` | `string` | `sni` | SNI hostname pattern for TLS pass-through routing |
| `strategy` | `string` | `strategy` | Load balancing strategy |
| `proxy_protocol` | `bool` | `proxy_protocol` | Enable PROXY protocol |
| `max_connections` | `int64` | `max_connections` | Max concurrent connections |
| `backends` | `[]Server` | `backend` blocks | Upstream TCP backends (use `tcp://` scheme) |
| `health_check` | `TCPHealthCheck` | `health_check` block | TCP health check |

### `health_check` block (TCP)

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `Enabled` | Enable health checking |
| `interval` | `Duration` | Check interval |
| `timeout` | `Duration` | Check timeout |
| `send` | `string` | String to send to backend |
| `expect` | `string` | Expected response string |

---

## `tls` block

Configures TLS for a host.

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `mode` | `TlsMode` | `mode` | TLS mode: `none`, `local`, `auto`, `letsencrypt`, `custom_ca` |
| `client_auth` | `string` | `client_auth` | mTLS mode: `none`, `request`, `require`, `require_and_verify`, `verify_if_given` |
| `client_cas` | `[]string` | `client_cas` | Absolute paths to client CA PEM files |
| `local` | `LocalCert` | `local` block | Manual certificate paths |
| `letsencrypt` | `LetsEncrypt` | `letsencrypt` block | ACME configuration |
| `custom_ca` | `CustomCA` | `custom_ca` block | Internal CA configuration |

**Default mode:** `letsencrypt` (if not specified).

### `tls.local` block

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `Enabled` | Enable manual cert |
| `cert_file` | `string` | Absolute path to certificate PEM file |
| `key_file` | `string` | Absolute path to private key PEM file |

### `tls.letsencrypt` block

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `Enabled` | Enable ACME |
| `email` | `string` | ACME account email |
| `staging` | `bool` | Use staging environment |
| `short_lived` | `bool` | Request short-lived certs |
| `pebble` | `Pebble` | Pebble ACME test server config |

### `tls.custom_ca` block

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `Enabled` | Enable custom CA |
| `root` | `string` | Absolute path to CA root PEM file |

---

## `health_check` block (HTTP)

Active HTTP health checking for proxy routes.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `Enabled` | — | Enable health checking |
| `path` | `string` | — | **Required.** Health check URL path |
| `interval` | `Duration` | `10s` | Check interval |
| `timeout` | `Duration` | `5s` | Check timeout (must be ≤ interval) |
| `threshold` | `int` | `3` | Consecutive failures before marking unhealthy |
| `method` | `string` | `GET` | HTTP method |
| `headers` | `map[string]string` | — | Custom headers to send |
| `expected_status` | `[]int` | `[200]` | Acceptable status codes |
| `expected_body` | `string` | — | Expected substring in response body |
| `latency_baseline_ms` | `int32` | — | Baseline latency for degradation detection |
| `latency_degraded_factor` | `float64` | — | Factor above baseline considered degraded |
| `accelerated_probing` | `bool` | `false` | Probe faster after failures |
| `synthetic_when_idle` | `bool` | `false` | Generate synthetic checks when no real traffic |

---

## `circuit_breaker` block

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `Enabled` | — | Enable circuit breaker |
| `threshold` | `int` | `5` | Failure count to open the circuit |
| `duration` | `Duration` | `30s` | How long the circuit stays open |

---

## `rate_limit` block (per-route)

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `enabled` | `Enabled` | `enabled` | Enable rate limiting |
| `ignore_global` | `bool` | `ignore_global` | Skip global rate limit rules |
| `use_policy` | `string` | `use_policy` | Name of a global policy to apply |
| `rule` | `RateRule` | `rule` block | Inline rate limit rule |

### `rate_limits` block (global)

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `Enabled` | Enable global rate limiting |
| `ttl` | `Duration` | Entry TTL |
| `max_entries` | `int` | Maximum tracked entries |
| `rules` | `[]RateRule` | `rule` blocks — named global rules |
| `policies` | `[]RatePolicy` | `policy` blocks — named reusable policies |

### `rule` block

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `name` | `string` | *(label)* | Rule name |
| `enabled` | `Enabled` | `enabled` | Enable this rule |
| `prefixes` | `[]string` | `prefixes` | Apply only to these path prefixes |
| `methods` | `[]string` | `methods` | Apply only to these HTTP methods |
| `requests` | `int` | `requests` | Max requests per window |
| `window` | `Duration` | `window` | Time window |
| `burst` | `int` | `burst` | Burst allowance (must be ≥ `requests`) |
| `key` | `string` | `key` | Header name to use as rate-limit key (blank = IP) |

### `policy` block

Same as `rule` but named (via label) for reuse across routes via `use_policy`.

---

## `cors` block

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `Enabled` | — | Enable CORS |
| `allowed_origins` | `[]string` | — | Allowed origins (use `["*"]` for any) |
| `allowed_methods` | `[]string` | — | Allowed HTTP methods |
| `allowed_headers` | `[]string` | — | Allowed request headers |
| `exposed_headers` | `[]string` | — | Headers exposed to browser |
| `allow_credentials` | `bool` | `false` | Allow cookies/auth (cannot combine with `*` origin) |
| `max_age` | `int` | — | Preflight cache duration in seconds |

---

## `cache` block

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `enabled` | `Enabled` | `enabled` | Enable caching |
| `driver` | `string` | `driver` | `memory` or `redis` |
| `ttl` | `Duration` | `ttl` | Cache entry TTL |
| `methods` | `[]string` | `methods` | HTTP methods to cache |
| `memory` | `MemoryCache` | `memory` block | Memory cache options |
| `redis` | `RedisCache` | `redis` block | Redis cache options |

### `memory` block

| Field | Type | Description |
|-------|------|-------------|
| `max_items` | `int` | Maximum cached items |

### `redis` block (cache)

| Field | Type | Description |
|-------|------|-------------|
| `host` | `string` | Redis host |
| `port` | `int` | Redis port |
| `password` | `string` | Redis password |
| `db` | `int` | Redis database number |
| `key_prefix` | `string` | Key prefix for cache entries |

---

## `compression` block

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `Enabled` | — | Enable compression |
| `type` | `string` | `gzip` | `gzip` or `brotli` |
| `level` | `int` | — | Compression level. Gzip: 0–9. Brotli: 0–11. |

---

## `headers` block

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `Enabled` | Enable header manipulation |
| `request` | `Header` | Modify request headers |
| `response` | `Header` | Modify response headers |

### `Header` (request/response)

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `Enabled` | Enable this direction |
| `set` | `map[string]string` | Set header (overwrite existing) |
| `add` | `map[string]string` | Add header (keep existing) |
| `remove` | `[]string` | Remove headers by name |

---

## `wasm` block

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `enabled` | `Enabled` | `enabled` | Enable WASM middleware |
| `module` | `string` | `module` | **Required.** Absolute path to `.wasm` file |
| `config` | `map[string]string` | `config` | Key-value config passed to module |
| `max_body_size` | `int64` | `max_body_size` | Max body size accessible to module |
| `access` | `[]string` | `access` | Capabilities: `headers`, `body`, `method`, `uri`, `config` |

---

## `firewall` block

### Global (`security.firewall`)

| Field | Type | Description |
|-------|------|-------------|
| `rules` | `[]Rule` | Firewall rules |
| `defaults` | `Defaults` | Default actions for dynamic/static matches |

### Route-level (`route.firewall`)

| Field | Type | Description |
|-------|------|-------------|
| `status` | `Enabled` | Enable firewall on this route |
| `rules` | `[]Rule` | Route-specific rules |

### `rule` block

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `name` | `string` | *(label)* | **Required.** Rule name |
| `description` | `string` | `description` | Human-readable description |
| `type` | `string` | `type` | `static`, `dynamic`, or `whitelist` |
| `action` | `string` | `action` | `block`, `throttle`, or `allow` |
| `duration` | `Duration` | `duration` | Block duration (for dynamic rules) |
| `priority` | `int` | `priority` | Lower number = higher priority |
| `match` | `Match` | `match` block | Match conditions |

### `match` block

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `Enabled` | Enable this match |
| `ip` | `[]string` | IP/CIDR match |
| `path` | `[]string` | Path match |
| `methods` | `[]string` | HTTP method match |
| `any` | `[]Condition` | Match if any condition is true |
| `all` | `[]Condition` | Match if all conditions are true |
| `none` | `[]Condition` | Match if no condition is true |
| `extract` | `Extract` | Extract a value for further matching |
| `threshold` | `Threshold` | Threshold-based matching |

### `Condition` block (`any`/`all`/`none`)

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `Enabled` | Enable this condition |
| `location` | `string` | Where to look: `ip`, `path`, `method`, `header`, `query`, `body`, `uri`, `bot` |
| `key` | `string` | Header name or query key |
| `operator` | `string` | Comparison operator |
| `value` | `string` | Value to compare |
| `pattern` | `string` | Regex pattern |
| `negate` | `bool` | Negate the match |
| `ignore_case` | `bool` | Case-insensitive comparison |

### `threshold` block (match)

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `Enabled` | Enable threshold |
| `count` | `int` | Threshold count |
| `window` | `Duration` | Time window |
| `track_by` | `string` | What to track: `ip`, `header:Name`, etc. |
| `group_by` | `string` | Grouping dimension |
| `on_exceed` | `string` | Action when exceeded |

---

## `basic_auth` block

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `enabled` | `Enabled` | `enabled` | Enable Basic Auth |
| `users` | `[]string` | `users` | User list as `"username:password"` or `"username:$2a$..."` (bcrypt) |
| `realm` | `string` | `realm` | Auth realm (shown in browser dialog) |

---

## `jwt_auth` block

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `enabled` | `Enabled` | `enabled` | Enable JWT auth |
| `secret` | `Value` | `secret` | **Required.** HMAC secret or RSA public key |
| `issuer` | `string` | `issuer` | Expected `iss` claim |
| `audience` | `string` | `audience` | Expected `aud` claim |
| `claims_to_headers` | `map[string]string` | `claims_to_headers` | Map JWT claim → request header |

---

## `forward_auth` block

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `enabled` | `Enabled` | `enabled` | Enable forward auth |
| `name` | `string` | *(label)* | Auth handler name |
| `url` | `string` | `url` | **Required.** Auth service URL |
| `on_failure` | `string` | `on_failure` | **Required.** `allow` or `deny` |
| `timeout` | `Duration` | `timeout` | **Required.** Request timeout |
| `tls` | `ForwardTLS` | `tls` block | TLS for auth service connection |
| `request` | `ForwardAuthRequest` | `request` block | Request forwarding options |
| `response` | `ForwardAuthResponse` | `response` block | Response handling |

### `forward_auth.request` block

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `Enabled` | Enable request forwarding config |
| `headers` | `[]string` | Headers to forward to auth service |
| `method` | `string` | Override HTTP method for auth request |
| `forward_method` | `bool` | Forward original request method |
| `forward_uri` | `bool` | Forward original request URI |
| `forward_ip` | `bool` | Forward client IP |
| `body_mode` | `string` | `none`, `metadata`, or `limited` |
| `max_body` | `int64` | Max body bytes to forward (for `limited` mode) |
| `cache_key` | `[]string` | Headers to include in auth cache key |

### `forward_auth.response` block

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `Enabled` | Enable response handling |
| `copy_headers` | `[]string` | Auth response headers to copy to upstream request |
| `cache_ttl` | `Duration` | How long to cache auth decisions |

### `forward_auth.tls` block

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `Enabled` | Enable custom TLS for auth connection |
| `insecure_skip_verify` | `bool` | Skip certificate verification |
| `client_cert` | `Value` | Client certificate PEM |
| `client_key` | `Value` | Client key PEM |
| `ca` | `Value` | CA certificate PEM |

---

## `o_auth` block

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `enabled` | `Enabled` | `enabled` | Enable OAuth |
| `provider` | `string` | `provider` | **Required.** `google`, `github`, or `oidc` |
| `client_id` | `string` | `client_id` | **Required.** OAuth client ID |
| `client_secret` | `Value` | `client_secret` | **Required.** OAuth client secret |
| `redirect_url` | `string` | `redirect_url` | **Required.** OAuth callback URL |
| `cookie_secret` | `Value` | `cookie_secret` | **Required.** Session cookie secret (min 16 chars) |
| `auth_url` | `string` | `auth_url` | Authorization endpoint (OIDC) |
| `token_url` | `string` | `token_url` | Token endpoint (OIDC) |
| `user_api_url` | `string` | `user_api_url` | User info endpoint (OIDC) |
| `scopes` | `[]string` | `scopes` | OAuth scopes |
| `email_domains` | `[]string` | `email_domains` | Restrict to these email domains |

---

## `gossip` block

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `enabled` | `Enabled` | `enabled` | Enable gossip clustering |
| `port` | `int` | `port` | Gossip port (default: `7946`) |
| `secret_key` | `Value` | `secret_key` | AES encryption key: 16, 24, or 32 bytes |
| `seeds` | `[]string` | `seeds` | Seed node addresses (`host:port`) |
| `ttl` | `int` | `ttl` | Gossip TTL |
| `shared_state` | `SharedState` | `shared_state` block | Distributed state backend |

### `shared_state` block

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `Enabled` | Enable shared state |
| `driver` | `string` | `memory` or `redis` |
| `redis` | `RedisState` | `redis` block — Redis connection |

---

## `admin` block

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `enabled` | `Enabled` | `enabled` | Enable admin server |
| `address` | `string` | `address` | **Required.** Bind address (e.g. `:9090`) |
| `allowed_ips` | `[]string` | `allowed_ips` | IP allowlist for admin access |
| `basic_auth` | `BasicAuth` | `basic_auth` block | Basic auth for admin |
| `forward_auth` | `ForwardAuth` | `forward_auth` block | Forward auth for admin |
| `jwt_auth` | `JWTAuth` | `jwt_auth` block | JWT auth for admin |
| `o_auth` | `OAuth` | `o_auth` block | OAuth for admin |
| `totp` | `TOTP` | `totp` block | TOTP two-factor authentication for admin logins |
| `pprof` | `Pprof` | `pprof` block | Go pprof server |
| `telemetry` | `Telemetry` | `telemetry` block | Telemetry export |

### `totp` block

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `Enabled` | Require TOTP code during admin login |

Setup with `agbero admin totp setup --user <username>`. See [Security Guide](./security.md).

### `pprof` block

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `Enabled` | Enable pprof |
| `bind` | `string` | Bind address or port (e.g. `:6060`) |

---

## `logging` block

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `enabled` | `Enabled` | `enabled` | Enable access logging |
| `level` | `string` | `level` | `debug`, `info`, `warn`, `error` |
| `diff` | `Enabled` | `diff` | Log only fields that changed between requests |
| `deduplicate` | `Enabled` | `deduplicate` | Suppress duplicate log lines |
| `truncate` | `Enabled` | `truncate` | Truncate long values |
| `bot_checker` | `Enabled` | `bot_checker` | Annotate bot requests |
| `skip` | `[]string` | `skip` | Path prefixes to exclude from logs |
| `include` | `[]string` | `include` | Only log these path prefixes |
| `file` | `FileLog` | `file` block | File-based logging |
| `victoria` | `Victoria` | `victoria` block | VictoriaMetrics/VictoriaLogs export |
| `prometheus` | `Prometheus` | `prometheus` block | Prometheus metrics endpoint |

### `file` block

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `Enabled` | Enable file logging |
| `path` | `string` | Log file path |
| `batch_size` | `int` | Write batch size |
| `rotate_size` | `int64` | Rotate at this file size (bytes) |

### `victoria` block

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `Enabled` | Enable Victoria export |
| `url` | `string` | VictoriaMetrics/VictoriaLogs endpoint URL |
| `batch_size` | `int` | Batch size for log shipping |

### `prometheus` block

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `Enabled` | Enable Prometheus metrics |
| `path` | `string` | Metrics endpoint path (default: `/metrics`) |

---

## `security` block

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `enabled` | `Enabled` | `enabled` | Enable security features |
| `trusted_proxies` | `[]string` | `trusted_proxies` | Trusted upstream proxy IPs/CIDRs for real IP extraction |
| `firewall` | `Firewall` | `firewall` block | Global firewall configuration |
| `keeper` | `Keeper` | `keeper` block | Keeper (encrypted secret store) configuration |

### `security.keeper` block

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `Enabled` | Keeper is a required component; this is advisory only |
| `passphrase` | `Value` | Master passphrase to unlock the keeper. Use `"env.AGBERO_PASSPHRASE"` in production to avoid plaintext in config. |
| `auto_lock` | `Duration` | Automatically lock the keeper after this period of inactivity |
| `logging` | `Enabled` | Enable keeper operation logging |
| `audit` | `Enabled` | Enable detailed audit trail for all secret reads and writes |

---

## `error_pages` block

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `pages` | `map[string]string` | `pages` | Map of HTTP status code → file path |
| `default` | `string` | `default` | Default error page for unmatched codes |

---

## `fallback` block

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `enabled` | `Enabled` | `enabled` | Enable fallback |
| `type` | `string` | `type` | **Required.** `static`, `redirect`, or `proxy` |
| `status_code` | `int` | `status_code` | HTTP status for static fallback |
| `body` | `string` | `body` | Response body for `static` type |
| `content_type` | `string` | `content_type` | Content-Type for `static` type |
| `redirect_url` | `string` | `redirect_url` | Redirect target for `redirect` type |
| `proxy_url` | `string` | `proxy_url` | Proxy target for `proxy` type |
| `cache_ttl` | `int` | `cache_ttl` | Cache duration in seconds |

---

## `rewrite` block

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `pattern` | `string` | `pattern` | **Required.** Go regular expression |
| `target` | `string` | `target` | **Required.** Replacement string (supports capture groups `$1`, `$2`, …) |

---

## `limits` block

| Field | Type | HCL key | Description |
|-------|------|---------|-------------|
| `max_body_size` | `int64` | `max_body_size` | Maximum request body size in bytes |

---

## Type Reference

| Type | Description |
|------|-------------|
| `Enabled` | Boolean-like: `true`/`false` or `"active"`/`"inactive"` |
| `Value` | String supporting `"env.VAR"` (environment variable), `"ss://ns/key"` (keeper secret), or a plain literal. Legacy `"env:VAR"` colon form also accepted. |
| `Duration` | Go duration string: `"10s"`, `"5m"`, `"1h30m"` |
| `Address` | `[scheme://]host[:port]` — scheme: `http`, `https`, `tcp` |
| `WebRoot` | Directory path string |
| `TlsMode` | One of: `none`, `local`, `auto`, `letsencrypt`, `custom_ca` |