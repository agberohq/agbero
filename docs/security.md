# Security Architecture

This guide covers Agbero's security primitives: the encrypted secret store (keeper), internal authentication, secret references in configuration, admin authentication, TOTP, and token revocation.

---

## The Keeper — Encrypted Secret Store

The keeper is an encrypted, passphrase-protected database (`data.d/keeper.db`) that holds:

- Internal Ed25519 authentication key (used to mint and verify service tokens)
- Admin per-user JWT secrets
- TOTP seeds for admin users
- Any secrets you store manually via `agbero keeper set`
- TLS certificates and private keys (when running with a keeper backend)

The keeper must be unlocked for Agbero to start. It is the single source of truth for all sensitive material — nothing sensitive needs to live in `agbero.hcl` as a plaintext value.

### Unlocking the Keeper

Agbero resolves the master passphrase in this order:

1. `keeper.passphrase` in `agbero.hcl`
2. `AGBERO_PASSPHRASE` environment variable
3. Interactive prompt (if running in a terminal)

For unattended deployments (system service, container), use `AGBERO_PASSPHRASE`:

```bash
AGBERO_PASSPHRASE=mypassphrase agbero run
```

Or in `agbero.hcl`:

```hcl
security {
  keeper {
    passphrase = "env.AGBERO_PASSPHRASE"
  }
}
```

### First-time Setup

On first run, if no `keeper.db` exists, Agbero creates one. If running interactively, you will be prompted to set a master passphrase. For non-interactive first-run, set `AGBERO_PASSPHRASE` before starting.

```bash
agbero init
AGBERO_PASSPHRASE=mypassphrase agbero run
```

---

## Secret References (`ss://`)

Any `Value`-typed field in your HCL configuration can reference a secret stored in the keeper using the `ss://` scheme:

```hcl
ss://namespace/key
```

At runtime, Agbero resolves this reference by looking up `namespace/key` in the keeper. If the keeper is locked or the key does not exist, the literal string is used as-is and an error is surfaced in logs.

**Examples:**

```hcl
route "/api" {
  basic_auth {
    enabled = true
    users   = ["admin:ss://auth/admin-password-hash"]
  }
}

route "/payments" {
  serverless {
    replay "stripe" {
      headers = {
        "Authorization" = "Bearer ss://integrations/stripe-key"
      }
    }
  }
}
```

**Storing secrets in the keeper:**

```bash
agbero keeper set auth/admin-password-hash "$2a$10$..."
agbero keeper set integrations/stripe-key "sk_live_..."
```

You can also use `env.VAR` for environment variables, or plain strings. The three forms can be mixed freely across your configuration.

---

## Internal Authentication — Ed25519 PPK

The `/auto/v1/` API endpoints are protected by Ed25519-signed JWT tokens. This system requires a one-time setup:

### Setup

```bash
# Generate and store the master key in the keeper
agbero secret key init

# Generate a service token
agbero secret token --service myapp --ttl 8760h
```

The output of `secret token` includes:
- The signed JWT token (use as `Authorization: Bearer <token>`)
- The token's JTI — keep this for revocation

### Service Scope Enforcement

A token issued for service `"myapp"` may only register routes for hosts whose name starts with the service name followed by `-` or `.`. Examples:

| Service Name | Allowed Hosts | Rejected Hosts |
|---|---|---|
| `myapp` | `myapp.example.com`, `myapp-123.internal` | `other.example.com`, `myapp` (no separator) |
| `api` | `api.internal`, `api-v2.example.com` | `api2.internal`, `application.com` |

Service names must be single labels — dots are not allowed (e.g. `myapp`, not `myapp.svc`).

### If the Internal Key is Missing

If `agbero secret key init` has not been run, the `/auto/v1/` endpoints are disabled and Agbero logs:

```
admin api disabled: security ppk (internal_auth_key) not configured
```

---

## Admin Authentication

The admin interface (UI and `/api/v1/` endpoints) uses a separate per-user HMAC-SHA256 JWT. The login flow:

1. `POST /login` with `{"username": "...", "password": "..."}` — password verified against bcrypt hash stored in keeper
2. If TOTP is enabled, a challenge token is returned; complete via `POST /login/challenge`
3. On success, an 8-hour JWT is returned
4. Use `POST /refresh` with the current token to extend without re-authenticating
5. `POST /logout` revokes the current token

### Admin User Passwords

Admin user passwords are stored in the keeper as bcrypt hashes. Only bcrypt hashes are accepted — plain text is rejected.

```bash
# Generate a bcrypt hash
agbero secret hash --password "mypassword"

# Store it in the keeper (the admin setup wizard does this automatically)
agbero keeper set auth/users/alice "$2a$10$..."
```

### IP Allowlist

Restrict admin access to specific IPs or CIDRs:

```hcl
admin {
  enabled     = true
  address     = ":9090"
  allowed_ips = ["10.0.0.0/8", "192.168.1.100"]
}
```

---

## TOTP (Two-Factor Authentication)

TOTP adds a second factor to admin logins using a time-based one-time password (Google Authenticator, Authy, etc.).

### Setup

```bash
# Generate and store a TOTP secret for a user
agbero admin totp setup --user alice

# Displays a QR code in the terminal — scan with your authenticator app
# Optionally save the QR code as a PNG
agbero admin totp setup --user alice --out qr.png
```

### Enable in Configuration

```hcl
admin {
  enabled = true
  address = ":9090"

  totp {
    enabled = true
  }
}
```

### Re-display QR Code

```bash
agbero admin totp qr --user alice
agbero admin totp qr --user alice --out qr.png
```

### Login Flow with TOTP

1. `POST /login` returns `{"status": "challenge_required", "token": "...", "requirements": ["totp"]}`
2. `POST /login/challenge` with `{"totp": "123456"}` and `Authorization: Bearer <challenge-token>`
3. Full admin JWT returned on success

---

## Token Revocation

### Revoking Service Tokens (`/auto/v1/`)

Service tokens can be revoked via the admin API using the JTI shown at generation time:

```bash
curl -X POST http://localhost:9090/api/v1/auto/revoke \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "jti": "abc123def456",
    "service": "myapp",
    "expires_at": "2025-03-15T10:30:00Z"
  }'
```

`expires_at` must match the token's actual expiry (shown at generation time). It is capped at 400 days from the current time to prevent store bloat. Tokens that are already expired are a no-op.

### Revoking Admin Sessions

`POST /logout` with a valid admin JWT immediately revokes that session. The token's JTI is added to an in-memory revocation set for its remaining lifetime.

---

## Trusted Proxies

When Agbero runs behind a load balancer or reverse proxy, configure trusted proxy IPs so that `X-Forwarded-For` is trusted for real client IP extraction:

```hcl
security {
  enabled         = true
  trusted_proxies = ["10.0.0.0/8", "172.16.0.0/12"]
}
```

Without this, Agbero uses `RemoteAddr` directly, and rate limiting and firewall rules will see the proxy IP instead of the real client IP.

---

## Development Mode

Setting `passphrase = "dev"` in the keeper config or `AGBERO_PASSPHRASE=dev` opens the keeper with a fixed insecure passphrase. **Never use this in production.**

```hcl
security {
  keeper {
    passphrase = "dev"
  }
}
```

---

## Next Steps

- **Keeper CLI**: See [Command Guide](./command.md#keeper--encrypted-secret-store) for all keeper operations
- **API Tokens**: See [API Guide](./api.md) for service token usage and revocation
- **Firewall**: See [Advanced Guide](./advance.md) for WAF and rate limiting
- **Admin Config**: See [Reference](./reference.md#admin-block) for all admin block fields
