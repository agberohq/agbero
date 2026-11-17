# Security Architecture

This guide covers Agbero's security primitives: the encrypted secret store (keeper), internal authentication, secret references in configuration, admin authentication, TOTP, and token revocation.

---

## Security Defaults (fail-closed)

Agbero prefers refusing traffic over silently running unprotected. These
behaviours are on by default and are worth knowing before you tune anything:

| Behaviour | What happens | Where to change it |
|-----------|--------------|--------------------|
| **Clustering needs a key** | `gossip.secret_key` is mandatory when gossip is enabled; startup fails without it. An unkeyed memberlist would accept config/certificate/secret injection from any peer that can reach the port | `gossip { secret_key = ... }` |
| **Admin `/status` is minimal when anonymous** | Only `/healthz` is fully public. `/status` returns just `{status, locked}` (the admin UI login probe); `telemetry` and `cluster_members` require a bearer token | — |
| **Credential endpoints are rate limited** | `/login` and `/login/challenge` share 10 req/min per IP (burst 10) even when `rate_limits` is not configured, and return `429` beyond that | `def.AdminAuthRate*` |
| **Challenge tokens are single-use** | The JWT ID is consumed atomically before TOTP/keeper verification, and removed when it expires | — |
| **JWT audience is enforced** | `jwt_auth.audience` rejects tokens whose `aud` does not match (`invalid_audience`); a token minted for another service on the same secret is not reusable | `jwt_auth { audience = ... }` |
| **Caching happens after auth** | The response cache sits *inside* the auth/WAF/firewall/rate-limit chain, so a cached body can never be served to an unauthenticated request | `route { cache { ... } }` |
| **Config output is redacted** | `/config`, `/config/global`, `/config/hosts` and the discovery API replace credentials with `***`: passwords, JWT/OAuth secrets, keeper passphrase and passphrase-file path, Redis password, tunnel and backend-tunnel credentials, forward-auth URL and client keys, WASM config | — |
| **Client certificates are verified** | `tls.client_auth` is applied per host at handshake time, so `require_and_verify` really does reject clients without a valid certificate | `tls { client_auth = ... client_cas = [...] }` |
| **Backend SSRF guards** | `security.block_private_backends` refuses dials to private/loopback/link-local IPs after DNS resolution; routes registered via the auto API always enforce it; `forward_auth` refuses private auth endpoints unless `allow_private = true` | `security.block_private_backends`, `forward_auth { allow_private = ... }` |
| **Serverless is opt-in** | Only bare command names listed in `security.allow.commands` can run (default `echo`), and git-backed workers need `security.allow.serverless_git = true` because a compromised repo equals code execution | `security { allow { ... } }` |
| **Rate limits degrade, not disappear** | If the Redis/cluster counter is unreachable the limiter falls back to per-node buckets and logs a warning, instead of allowing everything | `rate_limits { ... }` |
| **Bans survive reloads** | The firewall database is handed over to the replacement engine during a config reload, so bans recorded by the draining engine are still persisted | — |

---

## The Keeper — Encrypted Secret Store

The keeper is Agbero's built-in encrypted, passphrase-protected database. It is stored at `data.d/keeper.db` and holds everything sensitive that Agbero needs to operate:

- The internal Ed25519 authentication key (used to mint and verify service tokens for the `/auto/v1/` API)
- Admin per-user password hashes and JWT secrets
- TOTP seeds for admin users
- TLS certificates and private keys
- Any secrets you store manually via `agbero keeper set` or the Keeper REST API

**The keeper is a required component.** If it cannot be opened, Agbero does not serve secret-dependent traffic. A service may start in a locked/standby state so an operator can unlock it; it does not pretend to be fully operational while locked.

### Unlocking the Keeper

Agbero resolves the master passphrase in this order at startup:

1. systemd credential `$CREDENTIALS_DIRECTORY/keeper_passphrase`
2. `keeper.passphrase` in `agbero.hcl` (prefer an `env.` or `ss://` reference)
3. legacy `keeper.passphrase_file` (existing deployments only)
4. `AGBERO_KEEPER_PASSPHRASE` environment variable
5. `AGBERO_PASSPHRASE` environment variable (deprecated alias)
6. interactive terminal prompt
7. if none are available, a service starts **locked** and waits for `agbero keeper unlock`

`agbero init` no longer writes a passphrase file. Keeping the key next to `keeper.db` defeats at-rest encryption, so new installs do not create one.

Recommended unattended setup:

```ini
# systemd unit
LoadCredentialEncrypted=keeper_passphrase:/etc/agbero/keeper.cred
```

```bash
# or runtime injection
AGBERO_KEEPER_PASSPHRASE=mypassphrase agbero run
```

Manual unlock:

```bash
sudo agbero service start
agbero keeper unlock
```

`agbero service start` / `agbero service restart` prompt for the passphrase after starting a locked service. Direct `systemctl restart agbero` cannot prompt; run `agbero keeper unlock` afterward.

`LoadCredentialEncrypted` is preferred over `LoadCredential`: the latter's source is plaintext on disk, even though systemd copies it to a tmpfs at runtime.

### First-time Setup

On the very first run, if no `keeper.db` exists, Agbero creates one. If running interactively it prompts you to set a master passphrase. For non-interactive first-run, set `AGBERO_KEEPER_PASSPHRASE` before starting and Agbero will initialise the database with that passphrase automatically.

```bash
# Interactive first run
agbero init
agbero run
# -> prompts for passphrase, creates keeper.db, generates internal auth key

# Non-interactive first run (server, Docker)
AGBERO_KEEPER_PASSPHRASE=mypassphrase agbero run
# -> uses the env var, creates keeper.db silently, proceeds to start
```

### Keeper Configuration Block

You can tune keeper behaviour in `agbero.hcl` under the `security` block:

```hcl
security {
  keeper {
    # Master passphrase — use env var to avoid plaintext in config files
    passphrase = "env.AGBERO_KEEPER_PASSPHRASE"

    # Automatically lock the keeper after this period of inactivity.
    # Once locked, ss:// references return their literal string and log a warning
    # until you unlock with `agbero keeper unlock` (or the loopback-only API).
    auto_lock = "1h"

    # Log every keeper operation (open, read, write, delete) at INFO level
    logging = true

    # Full audit trail: logs the key name on every secret read and write.
    # Useful for compliance. Slightly higher log volume.
    audit = true
  }
}
```

### Development Mode

For local development you can use a fixed, well-known passphrase to avoid typing it every time:

```hcl
security {
  keeper {
    passphrase = "dev"
  }
}
```

> **Never use `passphrase = "dev"` in production.** The string `"dev"` is public knowledge. Anyone with read access to your `keeper.db` file can decrypt all your secrets using this passphrase. Use a strong, randomly-generated passphrase for any environment that handles real credentials.

---

## Secret References (`ss://`)

Any `Value`-typed field in your HCL configuration can reference a secret stored in the keeper using the `ss://` scheme. This is the primary way to keep credentials out of your config files and process arguments entirely.

```
ss://namespace/key
```

At runtime, when a request arrives, Agbero looks up `namespace/key` in the keeper and substitutes the value inline. The secret is never written to logs, never appears in the config file on disk, and never shows up in process arguments.

**This resolution happens at request time, not at config load time.** That means:
- You can rotate a secret with `agbero keeper set namespace/key newvalue` and the very next request will use the new value — no config reload, no restart.
- If the keeper is locked when a request arrives, the literal `ss://namespace/key` string is used as-is, which will cause API calls to fail with auth errors. Check keeper status if requests suddenly start failing with 401s.

### Example: JWT Secret

```hcl
# Without keeper — secret lives as an env var (still in your process environment)
route "/api/secure" {
  jwt_auth {
    enabled = true
    secret  = "${env.JWT_SECRET}"
  }
}

# With keeper — secret lives only in the encrypted database
route "/api/secure" {
  jwt_auth {
    enabled = true
    secret  = "ss://auth/jwt-secret"
  }
}
```

Store the secret:
```bash
agbero keeper set auth/jwt-secret "my-super-secret-jwt-key"
```

### Example: OAuth Client Secret

```hcl
route "/" {
  o_auth {
    enabled       = true
    provider      = "github"
    client_id     = "env.GITHUB_CLIENT_ID"        # ID is not sensitive, env var is fine
    client_secret = "ss://oauth/github-secret"    # Secret lives in keeper
    redirect_url  = "https://app.example.com/auth/callback"
    cookie_secret = "ss://oauth/cookie-secret"
  }
}
```

Store the secrets:
```bash
agbero keeper set oauth/github-secret "ghp_AbCdEf..."
agbero keeper set oauth/cookie-secret "random-32-char-string"
```

### Example: Backend Authorization Header

```hcl
route "/payments" {
  serverless {
    enabled = true
    replay "stripe" {
      url    = "https://api.stripe.com/v1/charges"
      method = "POST"
      headers = {
        "Authorization" = "Bearer ss://integrations/stripe-key"
      }
    }
  }
}
```

Store the key:
```bash
agbero keeper set integrations/stripe-key "sk_live_AbCdEf..."
```

### Example: Basic Auth Password Hash

```hcl
route "/admin" {
  basic_auth {
    enabled = true
    users   = ["admin:ss://auth/admin-bcrypt-hash"]
  }
}
```

Store the bcrypt hash (generate it with `agbero secret hash`):
```bash
agbero secret hash --password "mypassword"
# Output: $2a$10$K2ul0gaUotcRRqTWnq4TRu...
agbero keeper set auth/admin-bcrypt-hash '$2a$10$K2ul0gaUotcRRqTWnq4TRu...'
```

### Namespace and Key Rules

Namespaces and keys must follow these rules or the reference will be rejected:

| Part | Valid characters | Length |
|------|-----------------|--------|
| Namespace | `a-z A-Z 0-9 _ -` | 3–64 characters |
| Key | `a-z A-Z 0-9 _ . -` | 1–128 characters |

**Reserved namespaces** — these cannot be read or written via the Keeper API or `ss://` references from user config:

| Namespace | Used for |
|-----------|----------|
| `internal` and `internal/*` | Agbero's own internal keys (Ed25519 auth key, admin secrets, TOTP seeds) |
| `vault://` scheme | Internally managed vault secrets |

Attempting to set a key in a reserved namespace via the API returns `403 Forbidden`. Attempting to use `ss://internal/something` in HCL will log a warning and use the literal string.

### All Three Value Forms Together

`env.VAR`, `ss://`, and plain strings can be mixed freely in the same config:

```hcl
headers = {
  "X-Static"      = "my-fixed-header-value"        # plain string
  "X-Env-Var"     = "env.MY_API_KEY"               # from environment
  "Authorization" = "Bearer ss://auth/api-key"      # from keeper
}
```

The legacy `env:VAR` colon syntax is also accepted for backwards compatibility.

---

## Keeper REST API

When Agbero is running as a service, you manage the keeper through its REST API rather than the CLI. All endpoints are under `/api/v1/keeper/` and require an admin JWT obtained from `POST /login`.

### Check Keeper Status

```bash
curl http://localhost:9090/api/v1/keeper/status \
  -H "Authorization: Bearer <admin-token>"
```

Response:
```json
{
  "enabled": true,
  "locked": false
}
```

If `locked` is `true`, secret resolution is suspended. Unlock it before proceeding.

### Unlock the Keeper

Use this when the keeper has been locked (by `auto_lock`, or a service restart without a stored credential):

```bash
sudo agbero keeper unlock
```

The command prompts without echo and sends the passphrase over a root-only local control channel. It never writes the passphrase to disk or puts it in an environment variable.

`POST /api/v1/keeper/unlock` still exists for local bootstrap tooling, but it is loopback-only and requires the process to be running in locked mode. Prefer `agbero keeper unlock`.

Response:
```json
{"status": "unlocked"}
```

If the passphrase is wrong you get `401 Unauthorized` with `{"error": "invalid passphrase"}`.

### List All Keys

```bash
curl http://localhost:9090/api/v1/keeper/secrets \
  -H "Authorization: Bearer <admin-token>"
```

Response:
```json
{
  "keys": [
    "auth/jwt-secret",
    "integrations/stripe-key",
    "oauth/github-secret"
  ]
}
```

Note: reserved namespaces (`internal`, `vault://`) are excluded from the listing.

### Store a Secret (JSON)

```bash
curl -X POST http://localhost:9090/api/v1/keeper/secrets \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "key":   "integrations/stripe-key",
    "value": "sk_live_AbCdEf..."
  }'
```

Response:
```json
{
  "key":   "integrations/stripe-key",
  "bytes": 24,
  "ref":   "ss://integrations/stripe-key"
}
```

The `ref` field in the response is exactly what you paste into your HCL config.

### Store a Pre-encoded Base64 Value

If your value is already base64-encoded (e.g. a binary key), set `"b64": true` and Agbero will decode it before storing:

```bash
curl -X POST http://localhost:9090/api/v1/keeper/secrets \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "key":   "crypto/hmac-key",
    "value": "dGhpcyBpcyBhIDMyLWJ5dGUga2V5",
    "b64":   true
  }'
```

### Store a File (Certificate, SSH Key, PEM)

For binary or multi-line values like TLS certificates and SSH private keys, use multipart upload:

```bash
# Store a TLS certificate
curl -X POST http://localhost:9090/api/v1/keeper/secrets \
  -H "Authorization: Bearer <admin-token>" \
  -F "key=ssl/example-cert" \
  -F "file=@/path/to/example.crt"

# Store an SSH private key
curl -X POST http://localhost:9090/api/v1/keeper/secrets \
  -H "Authorization: Bearer <admin-token>" \
  -F "key=deploy/ssh-key" \
  -F "file=@~/.ssh/deploy_rsa"
```

Then reference in HCL:
```hcl
git {
  auth {
    type    = "ssh-key"
    ssh_key = "ss://deploy/ssh-key"
  }
}
```

### Get a Secret

The returned value is always base64-encoded. Decode it to get the raw bytes.

```bash
curl http://localhost:9090/api/v1/keeper/secrets/integrations/stripe-key \
  -H "Authorization: Bearer <admin-token>"
```

Response:
```json
{
  "key":      "integrations/stripe-key",
  "value":    "c2tfbGl2ZV9BYkNkRWYuLi4=",
  "encoding": "base64"
}
```

Decode on the command line:
```bash
echo "c2tfbGl2ZV9BYkNkRWYuLi4=" | base64 -d
# sk_live_AbCdEf...
```

You can also use `ss://` or the full path in the URL:
```bash
curl http://localhost:9090/api/v1/keeper/secrets/ss://integrations/stripe-key \
  -H "Authorization: Bearer <admin-token>"
```

### Delete a Secret

```bash
curl -X DELETE http://localhost:9090/api/v1/keeper/secrets/integrations/stripe-key \
  -H "Authorization: Bearer <admin-token>"
```

Response:
```json
{"deleted": "integrations/stripe-key"}
```

In cluster mode, the deletion is broadcast to all nodes — every node removes the key from its local keeper.

### Keeper API Error Reference

| Status | Meaning |
|--------|---------|
| `200 OK` | Success |
| `400 Bad Request` | Invalid key format or missing required field |
| `401 Unauthorized` | Wrong passphrase (unlock only) |
| `403 Forbidden` | Key is in a reserved namespace |
| `404 Not Found` | Key does not exist |
| `423 Locked` | Keeper is locked — unlock first |
| `503 Service Unavailable` | Keeper not configured |

---

## Internal Authentication — Ed25519 PPK

The `/auto/v1/` API endpoints (dynamic route management) are protected by Ed25519-signed JWT tokens. This system requires a one-time setup:

### Setup

```bash
# Generate and store the master Ed25519 key in the keeper (one-time per cluster)
agbero secret key init

# Generate a signed token for a service
agbero secret token --service myapp --ttl 8760h
```

The output of `secret token` shows:
```
API Token for service: myapp
JTI: abc123def456          ← keep this — needed to revoke the token later
Expires: 2026-03-15T10:30:00Z (8760h0m0s)
eyJhbGciOiJFZERTQSIs...    ← use this as "Authorization: Bearer <token>"
```

### Service Scope Enforcement

A token issued for service `"myapp"` may only register routes for hosts whose name starts with the service name followed by `-` or `.`. This prevents one service from hijacking another service's routes.

| Service Name | Allowed Hosts | Rejected Hosts |
|---|---|---|
| `myapp` | `myapp.example.com`, `myapp-123.internal` | `other.example.com`, `myapp2.internal` |
| `api` | `api.internal`, `api-v2.example.com` | `api2.internal`, `application.com` |

Service names must be single labels — dots are not allowed (e.g. `myapp`, not `myapp.svc`).

### If the Internal Key is Missing

If `agbero secret key init` has not been run, the `/auto/v1/` endpoints are silently disabled and Agbero logs:

```
admin api disabled: security ppk (internal_auth_key) not configured
```

Run `agbero secret key init` to generate and store the key, then restart.

---

## Admin Authentication

The admin interface (UI and `/api/v1/` endpoints) uses per-user HMAC-SHA256 JWTs. The full login flow:

1. `POST /login` with `{"username": "...", "password": "..."}` — password verified against bcrypt hash stored in the keeper
2. If TOTP is enabled, a challenge token is returned; complete via `POST /login/challenge`
3. On success, an 8-hour JWT is returned
4. Use `POST /refresh` with the current token to extend the session without re-authenticating
5. `POST /logout` immediately revokes the current session token

### Admin User Passwords

Admin user passwords are stored in the keeper as bcrypt hashes. Plain text is rejected.

```bash
# Generate a bcrypt hash for a password
agbero secret hash --password "mypassword"
# Output: $2a$10$K2ul0gaUotcRRqTWnq4TRu...

# The init wizard stores this automatically.
# To add a user manually:
agbero keeper set auth/users/alice '$2a$10$K2ul0gaUotcRRqTWnq4TRu...'
```

### IP Allowlist

Restrict the admin interface to specific IP addresses or CIDR ranges — useful when it binds on a public interface:

```hcl
admin {
  enabled     = true
  address     = ":9090"
  allowed_ips = ["10.0.0.0/8", "192.168.1.100", "::1"]
}
```

Requests from unlisted IPs receive `403 Forbidden` before any auth check is attempted.

---

## TOTP (Two-Factor Authentication)

TOTP adds a second factor to admin logins using a time-based one-time password (Google Authenticator, Authy, 1Password, etc.).

### Setup

```bash
# Generate and store a TOTP secret for a user, display QR code in terminal
agbero admin totp setup --user alice

# Save the QR code as a PNG file as well
agbero admin totp setup --user alice --out qr-alice.png
```

Scan the QR code with your authenticator app. On image-capable terminals (iTerm2, Kitty, WezTerm, Ghostty) the QR is rendered as an image; elsewhere Agbero prints a high-contrast ANSI QR. Override detection with `AGBERO_QR=image` or `AGBERO_QR=ansi`.

The terminal also prints the Base32 secret and `otpauth://` URI; if the QR cannot be rendered or scanned, enter the secret manually. The secret is shown once — if lost, run `totp setup` again to regenerate.

### Enable TOTP in Configuration

```hcl
admin {
  enabled = true
  address = ":9090"

  totp {
    enabled = true
  }
}
```

With TOTP enabled, the login flow becomes two steps:

**Step 1 — Submit credentials:**
```bash
curl -X POST http://localhost:9090/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "mypassword"}'

# Response when TOTP is required:
{
  "status":       "challenge_required",
  "token":        "eyJhbGci...",     ← short-lived challenge token
  "requirements": ["totp"]
}
```

**Step 2 — Submit the TOTP code from your authenticator:**
```bash
curl -X POST http://localhost:9090/login/challenge \
  -H "Authorization: Bearer eyJhbGci..."  \
  -H "Content-Type: application/json" \
  -d '{"totp": "123456"}'

# Response on success:
{
  "token":   "eyJhbGci...",     ← full 8-hour admin JWT
  "expires": "2024-01-16T10:30:00Z"
}
```

### Re-display QR Code

```bash
# Display in terminal again
agbero admin totp qr --user alice

# Save as PNG
agbero admin totp qr --user alice --out qr-alice.png
```

---

## Token Revocation

### Revoking Service Tokens (`/auto/v1/`)

If a service token is compromised, revoke it immediately using the JTI that was shown at generation time:

```bash
curl -X POST http://localhost:9090/api/v1/auto/revoke \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "jti":        "abc123def456",
    "service":    "myapp",
    "expires_at": "2026-03-15T10:30:00Z"
  }'

# Response
{"status": "ok", "jti": "abc123def456"}
```

`expires_at` must match the token's actual expiry (shown at generation time) and be in the future. Tokens that are already expired return `200 ok` with a message saying no action was needed — they are already invalid. The revocation store caps entries at 400 days to prevent unbounded growth.

### Revoking Admin Sessions

`POST /logout` with a valid admin JWT immediately revokes that session. The token's JTI is added to an in-memory revocation set for its remaining lifetime. After logout, the token returns `401 Unauthorized` on all endpoints.

---

## Trusted Proxies

When Agbero sits behind an upstream load balancer or proxy, the client IP seen by Agbero is the proxy's IP, not the real client. Configure trusted proxy CIDRs to tell Agbero which `X-Forwarded-For` entries to trust:

```hcl
security {
  enabled = true

  allow {
    proxies = [
      "127.0.0.0/8",      # loopback
      "10.0.0.0/8",       # private
      "172.16.0.0/12",    # private
      "192.168.0.0/16",   # private
    ]
  }
}
```

> **The key is `security.allow.proxies`, not `security.trusted_proxies`.**
> The HCL decoder ignores attributes it does not recognise, so a misspelled key
> produces no error — it is simply dropped. If the real client IP never shows up
> in logs, firewall decisions or rate-limit buckets, check that `proxies` sits
> inside the `allow` block.

Without this, rate limiting, firewall rules and `admin.allowed_ips` all see the
proxy's IP instead of the real client, meaning all traffic appears to come from
one address and your limits become useless. `X-Forwarded-For` is only consulted
when the immediate peer is inside `proxies`, so the list must contain the load
balancer, never `0.0.0.0/0`.

---

## Next Steps

- **Keeper CLI**: See [Command Guide](./command.md#keeper--encrypted-secret-store) for all CLI keeper operations
- **API Tokens**: See [API Guide](./api.md) for service token usage and the full Keeper API reference
- **Firewall**: See [Advanced Guide](./advance.md) for WAF and rate limiting
- **Admin Config**: See [Reference](./reference.md#admin-block) for all admin block fields
