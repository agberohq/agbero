# Host configuration examples

These files are **illustrative host configs**. Copy one into your live
`hosts.d/` directory, replace the domains, paths, addresses, and credentials,
then reload Agbero.

HCL supports `#` comments, so each example explains the non-obvious choices
instead of only listing fields. All examples in this directory are parsed and
parsed and structurally validated during authoring.

## Application and frontend examples

| File | Use case |
|---|---|
| `pocketbase.hcl` | Static SPA + PocketBase REST, admin, realtime SSE |
| `spa-node-api.hcl` | Static SPA with a separate Node API |
| `nextjs.hcl` | Next.js SSR server |
| `laravel-php.hcl` | Laravel/PHP-FPM |
| `static-spa.hcl` | Static site with client-side routes |
| `markdown-wiki.hcl` | Markdown documentation site |
| `git-pages.hcl` | Git-backed static site |
| `php.hcl` | Minimal PHP example |
| `web.hcl` | Minimal static web example |

## APIs, streaming, and credentials

| File | Use case |
|---|---|
| `replay-api.hcl` | Credential-injecting replay to third-party APIs |
| `relay-proxy.hcl` | Replay relay mode with `allowed_domains` |
| `api-gateway.hcl` | JWT, CORS, and rate limiting at the edge |
| `canary-deploy.hcl` | Weighted canary deployment |
| `websocket.hcl` | WebSocket upgrade route |
| `sse-events.hcl` | Long-lived Server-Sent Events |
| `serverless-worker.hcl` | HTTP-triggered worker processes |
| `maintenance-fallback.hcl` | Static maintenance fallback |

## Transport and infrastructure

| File | Use case |
|---|---|
| `tcp-postgres.hcl` | Raw TCP load balancing for PostgreSQL |
| `udp-dns.hcl` | UDP DNS load balancing |
| `cockroach.hcl` | CockroachDB TCP proxy |
| `consul.hcl` | Consul HTTP UI proxy |
| `full.hcl` | Broad reference with many blocks |
| `admin.hcl` | Admin-style host |
| `cors.hcl` | CORS configuration |
| `npm.hcl` | Node/npm application |
| `imigify.hcl` | Image service |
| `victoria.hcl` | VictoriaMetrics/Logs integration |

## Choosing the right route type

- **`backend`** — HTTP reverse proxy to your own application. Preserves
  cookies, Authorization headers, file downloads, SSE, and WebSocket upgrades.
- **`web`** — static files, optional PHP, Markdown, Git deployment.
- **`replay`** — Agbero calls a third-party API and injects credentials
  server-side. It is not for exposing your own application.
- **`proxy`** — raw TCP or UDP load balancing. It is not an HTTP route.

## Notes

- `route "/"` should usually be the least-specific route; `/api`, `/_`, `/ws`,
  etc. are matched more specifically.
- WebSocket and SSE clients require HTTP/1.1 for the upgrade/handshake. Use
  `curl --http1.1` when testing manually.
- Keep backend services bound to loopback or a private interface.
- Validate domain names, TLS contacts, and file paths before deploying.
