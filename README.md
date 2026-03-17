> WARNING: This project is under active development.

<p align="center">
  <img src="assets/agbero.2.png" width="300" alt="Agbero Logo">
</p>


[![Go Report Card](https://goreportcard.com/badge/github.com/agberohq/agbero)](https://goreportcard.com/report/github.com/agberohq/agbero)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)


### **Agbero**: *noun* [`Yoruba` ,`English`] - a motor-park tout or conductor who directs traffic, loads buses, checks tickets, and collects tolls.
##### **In Context**: This is exactly what a modern API Gateway does. It sits at the edge of your network, directs incoming API traffic to the right microservices, checks authentication ("tickets"), and enforces rate limits ("tolls").


Agbero is a modern reverse proxy that bridges local development and production deployments. It offers Zero-Config TLS for developers, Production-Grade Load Balancing, Git-based atomic deployments, and a Programmable WASM Data Plane.

## Why Choose Agbero?

<p align="center">
  <img src="assets/dash.1.png" width="500" alt="Agbero Dashboard">
</p>


### For Developers
- **Zero-Config Local HTTPS**: Run `agbero run` in any directory for instant HTTPS with auto-trusted certificates.
- **Hot Reload**: Modify configurations, routes, and WASM plugins without restarting or dropping connections.
- **Unified Config**: Use `${env.VAR}` syntax to make one configuration file work seamlessly across Dev, Staging, and Production.

<p align="center">
  <img src="assets/dash.2.png" width="500" alt="Agbero Dashboard">
</p>


### Scalable
- **Atomic Git Deployments**: Serve static sites and Single Page Applications (SPAs) directly from a Git repository with zero-downtime updates via Webhooks or interval polling.
- **Weighted Load Balancing**: Native support for canary deployments and A/B testing.
- **Built-in Gossip Protocol**: Automatic service discovery across nodes without external dependencies like Consul or Zookeeper.
- **Circuit Breaking & Health Checks**: Automatic failure detection, predictive health scoring, and rapid recovery.
- **HDR Histogram Metrics**: Detailed latency tracking (P50/P90/P99) exposed via JSON and the built-in Dashboard.

<p align="center">
  <img src="assets/dash.3.png" width="500" alt="Agbero Dashboard">
</p>


### Programmable & Extensible
- **WASM Middleware**: Write custom logic in Go, Rust, or TinyGo and run it safely inside the proxy.
- **Native Authentication**: Built-in support for JWT validation, OAuth (Google, GitHub, OIDC), Basic Auth, and Forward Auth.
- **Rate Limiting**: Identity-based limiting (API Key, IP, Cookie) with distributed sharding.

## Quick Start

### Installation

**Edge (development)**
```bash
curl -fsSL https://raw.githubusercontent.com/agberohq/agbero/refs/heads/main/scripts/install.sh | sh
```
**Release (stable)**
```bash
curl -fsSL https://github.com/agberohq/agbero/releases/latest/download/install.sh | sh
```

### The Simplest Possible Start

**1. Persistent Configuration** (Recommended for projects)
```bash
# Init in default location
agbero init

# Init in a specific directory
AGBERO_HOME=/etc/agbero agbero init

# Run Agbero using the generated configuration
agbero run --dev

# Or specify a custom configuration file
agbero run -c /etc/agbero/agbero.hcl
```

now visit `https://admin.localhost` in your browser.


**2. Instant Ephemeral Mode** (No config required)
```bash
# Serve the current directory on https://localhost:8000 with auto-generated TLS
agbero serve . --https

# Proxy localhost:3000 to https://app.localhost:8080
agbero proxy :3000 app.localhost --https
```

### Service Setup

```bash
# Interactive service installation (Systemd / Launchd / Windows Service)
sudo agbero service install

# Start the service
sudo agbero service start
```

## Performance

- **Latency**: ~1ms average, <3ms P99 for static file serving under 50k requests/sec
- **Throughput**: 50,000+ requests per second on modest hardware
- **Memory**: ~25MB idle, ~50MB under load
- **Connections**: 50k+ concurrent connections with HTTP/3 (QUIC) and TCP proxy support

### Real-World Benchmark (1M requests)

| Metric | Value |
|--------|-------|
| Total Requests | 1,000,000 |
| Duration | 19.77 seconds |
| Requests/sec | 50,574 |
| Average Latency | 1.0ms |
| P95 Latency | 1.6ms |
| **P99 Latency** | **2.7ms** |
| Fastest Response | 0.1ms |
| Slowest Response | 58.9ms |

All responses returned HTTP 200 with zero errors.

## Documentation

- **[Global Configuration](docs/global.md)**: Main config reference (`agbero.hcl`).
- **[Host Configuration](docs/host.md)**: Routes, backends, and TLS.
- **[Advanced Guide](docs/advance.md)**: Clustering, Git deployments, health scoring.
- **[Plugin Guide](docs/plugin.md)**: Writing WebAssembly middleware in Go and Rust.
- **[CLI Reference](docs/command.md)**: Command-line interface documentation.
- **[API Reference](docs/api.md)**: Dynamic route management API.

## Roadmap

- [x] Auto-TLS (Local & Let's Encrypt)
- [x] HTTP/3 (QUIC) support
- [x] TCP & HTTP Reverse Proxying
- [x] WebAssembly (WASM) middleware
- [x] Native Authentication (JWT, Basic, OAuth, Forward Auth)
- [x] Advanced rate limiting & Active Firewall
- [x] Gossip-based cluster state synchronization
- [x] Git-based atomic deployments
- [x] Admin Dashboard UI
- [x] Cluster Implementation
- [ ] Better Test Coverage
- [ ] Proper Documentation

## Architecture

Agbero acts as an intelligent **edge traffic controller** that manages incoming requests and routes them to the appropriate backend services. It handles TLS termination, routing logic, middleware execution, and load balancing before forwarding requests to application servers.

The architecture is built around a **high-performance Go runtime**, a **programmable WebAssembly middleware layer**, and a **distributed cluster model powered by a gossip protocol**.

```mermaid
flowchart TD

    A[Client / Browser] --> B[Agbero Edge Listener]

    B --> C[TLS Manager]
    C --> D[Routing Engine]

    D --> E[Middleware Pipeline]

    E --> F[WASM Plugins]
    E --> G[Authentication]
    E --> H[Rate Limiting]

    D --> I[Load Balancer]

    I --> J[Backend Services]

    J --> J1[API Services]
    J --> J2[Static Sites from Git]
    J --> J3[Microservices]

    B --> K[Cluster Layer]

    K --> L[Gossip Protocol]
    L --> M[Service Discovery]
    L --> N[State Replication]
```

## Contributing

We welcome contributions! Please see our [Contributing Guide](docs/contributor.md) for details.

1. Fork the repository.
2. Create a feature branch.
3. Add tests for your changes.
4. Submit a pull request.

## License

MIT License - see [LICENSE](LICENSE) for details.