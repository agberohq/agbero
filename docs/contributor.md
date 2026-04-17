# Contributing to Agbero

First off, thank you for considering contributing to Agbero! It is people like you who make Agbero a powerful, zero-dependency proxy for everyone.

## Development Environment Setup

To build and test Agbero locally, you need:
- **Go 1.26** or higher.
- `make` (optional, but recommended for build scripts).
- A C compiler (`gcc` or `clang`) for the macOS darwin build (required for the CGo seatbelt sandbox code in `internal/hub/orchestrator/process_darwin_cgo.go`).

### 1. Clone the Repository

```bash
git clone https://github.com/agberohq/agbero.git
cd agbero
```

### 2. Run Tests

Agbero relies heavily on concurrency and lock-free data structures. It is critical to run all tests with the race detector enabled before submitting any PR.

```bash
go test -count=1 ./... -race
```

### 3. Build the Binary

```bash
make build
# The binary will be output to bin/agbero
```

---

## Project Architecture

Understanding the project structure will help you navigate the codebase. Here is how a request flows through the system:

```
Incoming request
       │
       ▼
server.go (binds listeners, owns all managers)
       │
       ▼
internal/handlers/listener.go   ← accepts TCP/TLS connections
       │
       ▼
internal/handlers/routes.go     ← radix tree lookup, selects route
       │
       ▼
internal/middleware/*            ← WAF, rate limiter, auth, CORS, WASM, headers…
       │
       ▼
internal/handlers/xhttp/         ← HTTP reverse proxy to upstream backend
       │    (or)
internal/handlers/web/           ← static file serving / markdown / PHP
       │    (or)
internal/handlers/xserverless/   ← replay proxying and worker execution
       │    (or)
internal/handlers/xtcp/          ← TCP proxy (L4)
       │
       ▼
Backend / filesystem / subprocess
```

**Hot reload flow:**
```
file change in hosts.d/ → internal/handlers/routes.go (fsnotify watcher)
  → debounce (100ms)
  → reparse HCL
  → rebuild radix tree
  → atomic pointer swap (zero downtime, in-flight requests complete on old tree)
```

### Package Map

| Package | What it contains |
|---------|-----------------|
| `cmd/agbero/` | CLI entrypoints, service management (install/start/stop), ephemeral proxy/serve commands |
| `internal/core/alaye/` | HCL configuration structs — defines the full schema. Adding a feature usually starts here |
| `internal/core/woos/` | Constants, defaults, and cross-platform path resolution |
| `internal/core/zulu/` | Core utilities: lock-free counters, IP extractors, high-performance random generators |
| `internal/core/expect/` | `Value` type resolution — handles `env.VAR`, `ss://`, `b64.`, plain strings |
| `internal/handlers/` | The Data Plane — routing, HTTP/TCP backends, middleware integration |
| `internal/middleware/` | Pluggable request interceptors: WAF, Rate Limiting, CORS, WASM, JWT, OAuth, headers |
| `internal/hub/cluster/` | Gossip/TCP cluster engine based on HashiCorp `memberlist`, secret sync |
| `internal/hub/cook/` | GitOps deployment engine — atomic symlink swapping for static sites |
| `internal/hub/secrets/` | Keeper resolution and wiring — connects `ss://` references to the keeper store |
| `internal/hub/tlss/` | Certificate management, Local CA generation, Let's Encrypt ACME integration |
| `internal/hub/orchestrator/` | Worker process management — background daemons, cron, on-demand processes |
| `internal/hub/resource/` | HTTP transport pool and upstream connection management |
| `internal/operation/api/` | Admin REST API handlers: keeper, routes, certs, cluster, firewall, tokens |

### Key Design Relationships

- `core/alaye/` defines the config structs. `core/expect/` defines how `Value` fields resolve. Both are used throughout.
- `hub/secrets/` wires the keeper store to the `Value` resolver so `ss://` references work at request time.
- `hub/cluster/` receives `KeeperSnapshot` and `KeeperWrite` function pointers from `server.go` — this is how cluster secret sync works without a circular import.
- `operation/api/` holds the Keeper REST API. The `Keeper` struct there holds a `clusterBroadcaster` interface so writes are broadcast after local storage.

---

## Pull Request Process

1. **Discuss Major Changes:** If you plan to add a large feature (e.g., a new driver for shared state, or a new OAuth provider), please open an Issue first to discuss the architecture.
2. **Branching:** Fork the repository and create a feature branch (`feature/your-feature-name` or `fix/issue-description`).
3. **Testing:** Ensure unit tests cover your new logic. Run the race detector.
4. **Documentation:** If your change modifies the HCL configuration, update `docs/global.md`, `docs/host.md`, and `docs/advance.md`. If it adds or changes an API endpoint, update `docs/api.md`.
5. **Submit:** Open a PR against the `main` branch. Ensure your commit messages are descriptive.

---

## Code Style Guidelines

- **Zero Dependencies (Where Possible):** Agbero prides itself on being a single binary. Avoid importing massive third-party libraries for trivial tasks.
- **Lock-Free Fast Paths:** The Data Plane (`handlers/`, `middleware/`) must be as fast as possible. Avoid `sync.Mutex` on the hot path. Prefer `atomic` operations, `sync.Map`, or sharded maps.
- **No Panics:** Use graceful error handling. The proxy must never crash due to a malformed client request.
- **Nil Interface Safety:** Never assign a nil concrete pointer to an interface field. Use an explicit nil check before assignment (see the `NewKeeper` bug fix in `internal/operation/api/keeper.go` for a concrete example of why this matters).
