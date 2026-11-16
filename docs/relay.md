# Relay — Agbero-to-Agbero Reverse Tunnel

Relay exposes a local Agbero through a public Agbero without FRP and without opening an inbound port on the local side.

## Remote — deployed once

```hcl
# relay.example.com.hcl
domains = ["relay.example.com"]

tls {
  mode = "letsencrypt"
  letsencrypt {
    enabled = true
    email   = "ops@example.com"
  }
}

relay "agents" {
  listen {
    address  = "0.0.0.0"
    port     = 8443
    protocol = "https"
  }

  auth {
    method = "enrollment"
    token  = "ss://tunnel/relay-enroll"
  }

  policy {
    namespace       = ""                    # global IDs
    allow_http      = true
    allow_subdomain = true
    allow_tcp_ports = ["20000-20100"]
    allow_udp_ports = ["20000-20100"]
    max_agents      = 100
    max_streams     = 1000
  }
}
```

The remote does not need an `agent` block or an `allow_ids` list per site. Agents enroll once, and their identities and exposures are stored in Oshodi.

Generate the bootstrap secret once:

```bash
agbero keeper make tunnel/relay-enroll
```

Copy the printed value to the other node:

```bash
agbero keeper set tunnel/relay-enroll "<value>"
```

`namespace = ""` is the only implemented mode. Global IDs avoid multi-level wildcard certificates: `hello.relay.example.com` is covered by `*.relay.example.com`.

## Local

```hcl
# docs.localhost.hcl
domains = ["docs.localhost"]

agent "alice" {
  relay  = "https://relay.example.com:8443"
  enroll = "ss://tunnel/relay-enroll"
  local  = "http://127.0.0.1:8080"
}

route "/" {
  web {
    root    = "/Users/oleku/gopath/src/github.com/agberohq/agbero/docs"
    listing = true
    index   = ["index.md"]
    markdown { enabled = true }
  }

  expose "hello" {
    via       = "alice"
    path      = true
    subdomain = true
  }

  expose "postgres" {
    via = "alice"

    tcp {
      public_port = 15432
      local       = "127.0.0.1:5432"
    }
  }

  expose "dns" {
    via = "alice"

    udp {
      public_port = 15353
      local       = "127.0.0.1:53"
    }
  }
}
```

- `agent.local` is the local HTTP target for path/subdomain exposures.
- `enroll` is only the bootstrap. The issued credential is stored at `relay/agents/<name>/credential` in the local Keeper.
- `token` can be used instead of `enroll` for a pre-provisioned credential.
- `local_path` defaults to `/`; `local_host` optionally rewrites the Host header.
- `expose "hello"` derives both public names from the label:
  - `relay.example.com/hello`
  - `hello.relay.example.com`

## Enrollment

1. Local resolves `enroll` from its Keeper.
2. Agent connects over TLS and presents `{name, enrollment token}`.
3. Remote verifies the token, enforces `max_agents`, and creates `agent/<name>` in Oshodi.
4. Remote issues a random per-agent credential and returns it.
5. Local stores the credential in Keeper.
6. Subsequent connections use the credential; enrollment is skipped.
7. If the credential is rejected and `enroll` is still configured, the local credential is cleared and enrollment is retried.

Remote stores only a SHA-256 hash of the credential, never the plaintext.

## Oshodi

```text
relay_agents/<agent> {
  id, credential_hash, status, created_at, last_seen, exposures
}

relay_claims/<kind>:<key> -> agent
relay_routes/<base>/<agent> -> last registration
```

Claim keys:

```text
path:/hello
sub:hello
tcp:15432
udp:15353
```

Ownership is checked on every registration. An exposure already owned by another agent is rejected; the same agent re-registering is idempotent.

## Public routing

| Public | Agent | Local |
|---|---|---|
| `relay.example.com/hello/*` | `alice` | `http://127.0.0.1:8080` |
| `hello.relay.example.com/*` | `alice` | `http://127.0.0.1:8080` |
| `relay.example.com:15432` | `alice` | `127.0.0.1:5432` |
| `relay.example.com:15353/udp` | `alice` | `127.0.0.1:53` |

## Transport

- HTTP path and subdomain use the remote's normal TLS termination.
- Subdomain mode creates an ephemeral remote host entry so TLS and host lookup work.
- TCP uses one tunnel connection per accepted public connection.
- UDP uses framed datagrams over the tunnel, with one flow per client address.
- `max_streams` limits pooled tunnel connections per agent session.

## Reload

Relay listeners and agents rebuild on config reload. Existing sessions reconnect with their stored credentials.

## Limitations

- `namespace` values other than `""` are rejected until agent-namespaced public naming is implemented.
- Subdomain mode requires wildcard DNS and a wildcard or on-demand certificate.
- TCP/UDP are raw; the relay does not add TLS.
- Revocation is enforced from the Oshodi `status` field, but there is no relay-agent admin UI yet.
- Relay sessions are node-local; a different remote node does not take over an agent session.
