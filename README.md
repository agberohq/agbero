<p align="center">
  <img src="assets/agbero.2.png" width="300" alt="Agbero Logo">
</p>

> **Agbero**: *noun* (Yoruba) - A tout or traffic controller at a bus stop.
> **In Context**: A high-performance, production-ready Reverse Proxy and Load Balancer written in Go.

[![Go Report Card](https://goreportcard.com/badge/github.com/agberohq/agbero)](https://goreportcard.com/report/github.com/agberohq/agbero)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Agbero is a modern reverse proxy that bridges local development and production deployments. It offers **Zero-Config TLS for developers**, **Production-Grade Load Balancing**, and a **Programmable WASM Data Plane**.

## ✨ Why Choose Agbero?

### 🚀 For Developers
- **Zero-Config Local HTTPS**: Run `agbero run` in any directory for instant HTTPS with auto-trusted certificates.
- **Hot Reload**: Modify configurations and WASM plugins without restarting.
- **Unified Config**: Use `${env.VAR}` syntax to make one config work for Dev and Prod.

### 🏭 For Production
- **Weighted Load Balancing**: Native support for canary deployments and A/B testing.
- **Built-in Gossip Protocol**: Automatic service discovery without external dependencies (Consul/Zookeeper).
- **Circuit Breaking & Health Checks**: Automatic failure detection and recovery.
- **HDR Histogram Metrics**: Detailed latency tracking (P50/P90/P99) exposed via JSON.

### 🔌 Programmable & Extensible
- **WASM Middleware**: Write custom logic in Go, Rust, or TinyGo and run it safely inside the proxy.
- **Native Authentication**: Built-in JWT validation and Forward Auth.
- **Rate Limiting**: Identity-based limiting (API Key/IP) with distributed sharding.


<p align="center">
  <img src="assets/dash.1.png" width="500" alt="Agbero Logo">
</p>

## 🚀 Quick Start


### Installation

```bash
# Download latest release
curl -L https://github.com/your-org/agbero/releases/latest/download/agbero-linux-amd64 -o agbero
chmod +x agbero
sudo mv agbero /usr/local/bin/

# Or build from source
go install github.com/agberohq/agbero/cmd/agbero@latest
```

### The Simplest Possible Start

```bash
# Serves current directory on https://localhost:8443 with auto-generated TLS
agbero run
```

### Production Setup

```bash
# Interactive service installation (Systemd/Launchd/Windows Service)
sudo agbero install

# Start the service
sudo agbero start
```

## 📋 Core Features

### 1. Smart TLS Management
- **Development**: Auto-generates and trusts local CA certificates (mkcert style).
- **Production**: Automatic Let's Encrypt with DNS challenge support.
- **Custom CAs**: Bring your own certificate authority.

### 2. Advanced Load Balancing & Routing
```hcl
route "/api" {
  backend {
    strategy = "weighted_round_robin"
    
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

### 3. Programmable WASM Middleware
Extend Agbero with custom logic written in any language that compiles to WASM.

```hcl
route "/secure" {
  wasm {
    module = "./plugins/auth.wasm"
    access = ["headers"] # Security: Grant specific permissions
    config = {
      "role" = "admin"
    }
  }
  
  backend {
    server { address = "http://app:8080" }
  }
}
```

### 4. Built-in Service Discovery (Gossip)
Services can auto-discover each other using the SWIM gossip protocol.

```bash
# Initialize gossip cluster
agbero gossip init

# Generate token for services
agbero gossip token --service payment-api --ttl 720h
```

### 5. Secure Configuration
Agbero supports dynamic configuration values to keep secrets out of files.

```hcl
gossip {
  # Load from environment variable
  secret_key = "${env.GOSSIP_SECRET}" 
}

route "/protected" {
  jwt_auth {
    # Load from Base64 string
    secret = "${b64.SGVsbG8gd29ybGQ=}" 
  }
}
```

## 📊 Performance

- **Throughput**: 50k+ requests/second on 4 vCPU
- **Latency**: <1ms P99 for static file serving
- **Memory**: ~15MB idle, ~50MB under load
- **Connections**: 10k+ concurrent connections with HTTP/3 (QUIC)

## 📚 Documentation

- **[GUIDE.md](docs/GUIDE.md)**: Practical examples, use cases, and tutorials.
- **[PLUGIN.md](docs/PLUGIN.md)**: Guide to writing WebAssembly middleware in Go and Rust.
- **[CLI Reference](cmd/agbero/README.md)**: Command-line interface documentation.
- **[Examples](examples/)**: Ready-to-run configuration examples.


## 🛣 Roadmap

- [x] Auto-TLS (Local & Let's Encrypt)
- [x] HTTP/3 (QUIC) support
- [x] Gossip-based service discovery
- [x] Advanced rate limiting (Identity based)
- [x] WebAssembly (WASM) middleware
- [x] Native JWT Authentication
- [ ] OpenTelemetry integration
- [ ] Dashboard UI

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch
3. Add tests for your changes
4. Submit a pull request

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.