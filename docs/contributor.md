# Contributing to Agbero

First off, thank you for considering contributing to Agbero! It is people like you who make Agbero a powerful, zero-dependency proxy for everyone.

## Development Environment Setup

To build and test Agbero locally, you need:
- **Go 1.26** or higher.
- `make` (optional, but recommended for build scripts).

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

## Project Architecture

Understanding the project structure will help you navigate the codebase:

- `cmd/agbero/`: The CLI entrypoints, service management (install/start/stop), and ephemeral proxy/serve commands.
- `internal/core/alaye/`: The configuration parser structs. This defines the HCL schema. If you add a feature, it usually starts by defining the configuration here.
- `internal/core/woos/`: Constants, defaults, and cross-platform path resolution.
- `internal/core/zulu/`: Core utilities (e.g., lock-free counters, IP extractors, high-performance random generators).
- `internal/discovery/`: The `fsnotify` watcher that monitors `hosts.d` and `certs.d`, handles debouncing, and compiles the radix tree for routing.
- `internal/handlers/`: The Data Plane. Contains the routing logic, HTTP/TCP backends, and integration with middleware.
- `internal/middleware/`: Pluggable request interceptors (WAF, Rate Limiting, CORS, WASM, JWT, OAuth).
- `internal/cluster/`: The Gossip/TCP cluster engine based on HashiCorp `memberlist`.
- `internal/pkg/cook/`: The GitOps deployment engine that handles atomic symlink swapping for static sites.
- `internal/pkg/tlss/`: Certificate management, Local CA generation (mkcert replacement), and Let's Encrypt ACME integrations.

## Pull Request Process

1. **Discuss Major Changes:** If you plan to add a large feature (e.g., a new  driver for shared state, or a new OAuth provider), please open an Issue first to discuss the architecture.
2. **Branching:** Fork the repository and create a feature branch (`feature/your-feature-name` or `fix/issue-description`).
3. **Testing:** Ensure unit tests cover your new logic. Run the race detector.
4. **Documentation:** If your change modifies the HCL configuration, update `docs/global.md`, `docs/host.md` and `docs/advance.md`.
5. **Submit:** Open a PR against the `main` branch. Ensure your commit messages are descriptive.

## Code Style Guidelines

- **Zero Dependencies (Where Possible):** Agbero prides itself on being a single binary. Avoid importing massive third-party libraries for trivial tasks.
- **Lock-Free Fast Paths:** The Data Plane (`handlers/`, `middleware/`) must be as fast as possible. Avoid `sync.Mutex` on the hot path. Prefer `atomic` operations, `sync.Map`, or `mappo.Sharded`.
- **No Panics:** Use graceful error handling. The proxy must never crash due to a malformed client request.