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
- The agent keeps one TLS connection to the relay, multiplexed with yamux. The first stream carries the control protocol; the relay opens one work stream per HTTP request, per accepted TCP connection, or per UDP client flow.
- There is no pool of pre-dialed data connections. An idle session holds no local connections, so the local listener's read-header timeout cannot kill the tunnel.
- TCP uses one work stream per accepted public connection. UDP uses framed datagrams on one work stream per client address.
- `max_streams` limits concurrent work streams per agent session.
- The relay rewrites the HTTP request (path and Host) before writing it to the work stream; the agent only dials the local target and joins the stream to it. HTTP local connections are dialed lazily, on the first bytes of a request.
- yamux keepalive runs every 30 seconds. When the relay advertises it during registration, the agent also pings the control stream every 25 seconds.
- Agents and relays must run the same mux protocol. A relay detects the yamux handshake by its first bytes and still serves the read-only check protocol on the same port; agents built before the mux protocol receive an explicit upgrade error instead of hanging.

## Reload

Relay listeners and agents rebuild on config reload. Existing sessions reconnect with their stored credentials.

## Limitations

- `namespace` values other than `""` are rejected until agent-namespaced public naming is implemented.
- Subdomain mode requires wildcard DNS and a wildcard or on-demand certificate.
- TCP/UDP are raw; the relay does not add TLS.
- Revocation is enforced from the Oshodi `status` field, but there is no relay-agent admin UI yet.
- Relay sessions are node-local; a different remote node does not take over an agent session.

## Doctor

`agbero relay doctor <agent>` is the primary diagnostic. It finds the agent
wherever it can be observed — in the local configuration when this host runs the
agent, in the live relay state when this host runs the relay, both when both are
present — and runs every check it can:

| Stage | What it proves |
|---|---|
| configuration | agent block, exposes and local target resolve |
| relay URL | endpoint parses with a usable host and port |
| enrollment | the token or Keeper reference resolves |
| dns | the relay hostname resolves |
| tls | handshake, certificate subject and expiry |
| authentication | the relay accepts the credential |
| local target | the local agbero answers for this Host/SNI |
| public /show | request and response cross the tunnel, payload matches |
| session | relay-side session: connected age, streams, reconnects, last error |
| route /show | the relay route exists and is bound to a live session |
| tcp / udp | the relay listener exists for raw exposures |

Each stage is `PASS`, `WARN`, `FAIL` or `SKIP`, the summary counts them, and the
command exits non-zero on any `FAIL`. Warnings (certificate close to expiry,
reconnects) do not fail the run.

```
$ agbero relay doctor alice
alice — client side, host show.localhost
configuration  PASS  1 expose(s), local https://127.0.0.1:443, sni show.localhost
relay URL      PASS  relay.example.com:8443
enrollment     PASS  enrollment secret resolves
dns            PASS  203.0.113.10
tls            PASS  relay.example.com, issuer R3, expires in 89d
authentication PASS  relay accepted the credential
local target   PASS  HTTP 200 in 2ms (10939 B) https://127.0.0.1:443
public /show   PASS  HTTP 200 in 41ms (10939 B), payload matched
alice: 8 passed, 0 failed, 0 warnings, 0 skipped
```

When a path is unstable the public stage reports the attempt chain, for example
`flapped: 502 → 502 → 200 — the path is not stable`, and the run fails even
though a retry eventually succeeded.

On the relay host the live state is read from the admin API. If it is protected,
pass `--admin-token` or set `AGBERO_ADMIN_TOKEN`.

`agbero relay check` remains available for a single explicit target and for
scripted probes; both commands share the same probing and verdict logic.

## Diagnosing failures

`agbero relay check` probes both legs and reports which layer failed instead of
only the public status. The public request is retried with exponential backoff
(`--attempts`, `--wait`, `--timeout`), every attempt is printed, and the command
exits non-zero when the path fails or flaps. A path that fails and then succeeds
is reported as flapping: retries must not turn a broken tunnel into a green
check.

The client check probes the local target and the public URL with the same path,
then compares them:

| Local control | Public | Meaning |
|---|---|---|
| 2xx | 2xx, same payload size | payload verified end to end |
| 2xx | 404 | the relay has no live route for the exposure |
| 2xx | 502/503/504 | the relay matched the route but the tunnel failed |
| fails | same status | the local target or local route is the problem |

On the relay host, `--server` also reads the live relay state from the admin API
(`/api/v1/relay`) and prints the route table and agent sessions with the
verdict. A 404 can then be attributed to a missing exposure, a route bound to a
closed session, or host matching.

Where each signal is explained:

- `404 Not found` with a healthy local control: no live route. Relay admin →
  Routes shows the key and session state; Agents shows `reconnects`.
- `502 Relay unavailable`: the route matched but the tunnel failed. Look at the
  agent session, its last error, and whether `reconnects` is climbing.
- Transport errors: DNS, TLS, or port reachability, before any agbero component.
- 2xx with a different payload size: traffic flows; the difference is content
  or middleware.

The relay admin page shows the live route table (route, agent, local target,
live or dead) and, per agent, the connected age, reconnect count, streams,
bytes, and last error with its age.
