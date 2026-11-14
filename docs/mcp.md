# MCP

Agbero exposes a read/plan-only MCP control plane and can label a route as
MCP-aware on the traffic plane. There is no write, apply, rollback, or delete
capability in MCP. A human applies changes through the admin UI, CLI, or Git.

## Control plane

When `mcp.enabled = "on"`, the daemon mounts the Streamable HTTP endpoint at
`/mcp` on the admin listener. It speaks the current stateless MCP revision and
the two legacy revisions supported by the SDK.

```hcl
mcp {
  enabled    = "on"
  transport  = "stdio"          # stdio for the CLI; the daemon also serves /mcp
  allowed_ips = ["127.0.0.1/32", "::1/128"]
  rate_limit = "60/m"
  audit_file = ""               # default: data_dir/mcp-audit.jsonl

  read {
    enabled = "on"
    allow   = ["status", "system", "config.global", "config.hosts",
               "config.host", "config.effective", "config.validate",
               "config.diff", "config.explain", "routes.explain",
               "security.review", "certs.list", "firewall.list",
               "cache.stats", "cluster.status"]
  }

  plan {
    enabled = "on"
    allow   = ["config.plan", "config.validate", "config.diff"]
  }
}
```

`allowed_ips` defaults to loopback. Explicit CIDRs replace the default; include
loopback if local access is still wanted. `0.0.0.0/0` and `::/0` are rejected.

The HTTP chain is:

```text
allowed_ips -> bearer token -> audit -> rate limit -> MCP handler
```

Tokens are keeper-backed HMAC JWTs:

```bash
agbero mcp token create --user alice --scope "mcp:read mcp:plan" --ttl 8h
agbero mcp token rotate
agbero mcp token revoke <jti>
```

A token with `mcp:plan` also has read access. `mcp:apply` and `mcp:admin` do not
exist. Send the token as `Authorization: Bearer <token>`.

### Admin page

The admin UI has an **MCP** page with three tabs:

- **Tokens** — status cards (including request/transfer counters), token
  creation, clean one-time copy, recent token metadata (JTI/scope/expiry/
  revoked; never the token itself), per-row revoke with a two-step confirm,
  and the **Enable/Remove https://mcp.localhost** action.
- **Audit** — recent JSONL audit records, including token mint/revoke and host
  enable/remove events.
- **Policy** — the capability → class → tool table.

The public host is not created automatically. The button writes
`hosts.d/mcp.localhost.hcl` only when pressed, and never overwrites an existing
host. A managed host can be removed from the same card, after confirmation;
user-created hosts are never removed. The generated route maps `https://mcp.localhost` (root) to the admin
listener's `/mcp/` endpoint, so the rest of the admin surface is not exposed.

It is backed by admin-JWT endpoints:

- `GET /api/mcp/admin/status`
- `POST /api/mcp/admin/token`
- `DELETE /api/mcp/admin/token/{jti}`
- `GET /api/mcp/admin/audit?lines=200`
- `POST /api/mcp/admin/host`

## Traffic plane

A normal route can forward MCP traffic, but it is not session-aware by default.
Set `protocol = "mcp"` to make the route MCP-aware:

```hcl
route "/mcp" {
  protocol = "mcp"

  backend {
    strategy = "sticky"
    keys     = ["header:Mcp-Session-Id"]
    server { address = "http://127.0.0.1:9001" }
  }
}
```

- `Mcp-Session-Id` is used for session affinity; `2025-11-25` and older
  sessionful clients stay on one backend.
- Compression and response caching are disabled for the route, so SSE/event
  streams are not buffered or transformed.
- Headers pass through unchanged.
- The route is labeled **MCP** on the admin map.
- The current stateless revision does not send a session ID; it falls through to
  the normal balancer.

This is not a full MCP proxy: there are no JSON-RPC method metrics and no
protocol-aware health check. Use a normal HTTP health path or `server/discover`.

## Offline and local transports

```bash
agbero mcp serve          # stdio, spawned by the MCP client
agbero mcp status         # configured classes/transport/allowlist
agbero mcp policy         # capability registry
```

With `mcp.transport = "unix"`, `agbero mcp serve` listens on `mcp.socket` (or
`data_dir/mcp.sock`). The socket is `0660` and local-only; HTTP `/mcp` is the
token-authenticated network surface.

Offline stdio mode can read configuration and run validation/plan tools, but
runtime tools (`certs`, `firewall`, `cache`, `cluster`) return
`admin_plane_required`. Use the daemon endpoint for live data.

## What MCP cannot do

- No `config_apply`, `config_rollback`, plan store, approval store, or cluster
  apply.
- No host/route/cert deletion.
- No firewall or cache mutation.
- No cluster join/leave.
- No keeper/secret export.
- No `logs_tail` yet; logs await a redaction specification.

Audit records contain actor, client IP, JSON-RPC method/tool, status, and
duration. They never contain request arguments or secrets.
