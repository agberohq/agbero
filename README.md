<p align="center">
  <img src="assets/agbero.2.png" width="300" alt="Agbero Logo">
</p>

> WARNING: This project is under active development.

> **Agbero**: *noun* (Yoruba) - A tout or traffic controller at a bus stop.
>
> **In Context**: A high-performance, production-ready Reverse Proxy and Load Balancer written in Go.

[![Go Report Card](https://goreportcard.com/badge/github.com/agberohq/agbero)](https://goreportcard.com/report/github.com/agberohq/agbero)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Agbero is a modern reverse proxy that bridges local development and production deployments. It offers Zero-Config TLS for developers, Production-Grade Load Balancing, Git-based atomic deployments, and a Programmable WASM Data Plane.

<p align="center">
  <img src="assets/dash.1.png" width="500" alt="Agbero Dashboard">
</p>

## Why Choose Agbero?

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

### Programmable & Extensible
- **WASM Middleware**: Write custom logic in Go, Rust, or TinyGo and run it safely inside the proxy.
- **Native Authentication**: Built-in support for JWT validation, OAuth (Google, GitHub, OIDC), Basic Auth, and Forward Auth.
- **Rate Limiting**: Identity-based limiting (API Key, IP, Cookie) with distributed sharding.

<p align="center">
  <img src="assets/dash.3.png" width="500" alt="Agbero Dashboard">
</p>

## Quick Start

### Installation

```bash
# Download latest release
curl -L https://github.com/agberohq/agbero/releases/latest/download/agbero-linux-amd64 -o agbero
chmod +x agbero
sudo mv agbero /usr/local/bin/

# Or build from source
go install github.com/agberohq/agbero/cmd/agbero@latest
```


### The Simplest Possible Start

**1. Persistent Configuration** (Recommended for projects)
```bash
# crate a new configuration directory
mkdir -p /etc/agbero
cd /etc/agbero

# Scaffold a new configuration workspace in the current directory
agbero init

# Run Agbero using the generated configuration
agbero run

# Or specify a custom configuration file
agbero run -c /etc/agbero/agbero.hcl 
```

**2. Instant Ephemeral Mode** (No config required)
```bash
# Serve the current directory on https://localhost:8000 with auto-generated TLS
agbero serve --https

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


## Core Features

### 1. Git-Based Atomic Deployments
Deploy static sites and SPAs directly from your Git provider. Agbero securely clones your repository and performs atomic directory swaps with zero downtime when a webhook is triggered.

```hcl
route "/app" {
  strip_prefixes = ["/app"]
  web {
    spa = true
    git {
      enabled = true
      id      = "frontend-app"
      url     = "https://github.com/your-org/spa-builds.git"
      branch  = "main"
      secret  = "env.GITHUB_WEBHOOK_SECRET"
    }
  }
}
```

### 2. Smart TLS Management
- **Development**: Auto-generates and trusts local CA certificates.
- **Production**: Automatic Let's Encrypt with HTTP-01 challenge and cluster-wide certificate replication.
- **Custom CAs**: Bring your own certificate authority.

### 3. Advanced Load Balancing & Routing
```hcl
route "/api" {
  backend {
    strategy = "weighted_least_conn"
    
    # Canary deployment: 10% traffic to new version
    server {
      address = "http://v2-service:8080"
      weight  = 10
    }
    
    # Stable version: 90% traffic
    server {
      address = "http://v1-service:8080"
      weight  = 90
    }
  }
}
```

## Performance

- **Throughput**: 50k+ requests/second on 4 vCPU.
- **Latency**: <1ms P99 for static file serving.
- **Memory**: ~15MB idle, ~50MB under load.
- **Connections**: 10k+ concurrent connections with HTTP/3 (QUIC) and TCP proxy support.

## Documentation

- **[GUIDE.md](docs/GUIDE.md)**: Practical examples, use cases, and tutorials.
- **[PLUGIN.md](docs/PLUGIN.md)**: Guide to writing WebAssembly middleware in Go and Rust.
- **[CLI Reference](cmd/agbero/README.md)**: Command-line interface documentation.
- **[Examples](examples/)**: Ready-to-run configuration examples.

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
- [ ] Proper Documentation 

## Contributing

We welcome contributions! Please see our [Contributing Guide](docs/contributor.md) for details.

1. Fork the repository.
2. Create a feature branch.
3. Add tests for your changes.
4. Submit a pull request.

## License

MIT License - see[LICENSE](LICENSE) for details.