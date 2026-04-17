# Agbero

**The Cloud-Native Reverse Proxy & Load Balancer for Modern Infrastructure**

Agbero is a high-performance, single-binary reverse proxy and API gateway designed to bridge the gap between the simplicity of traditional proxies (like Nginx or Caddy) and the advanced distributed capabilities of service meshes (like Istio or Envoy).

Whether you are running a single homelab server, deploying a globally distributed API, or serving static frontends directly from Git, Agbero provides a unified, zero-dependency control plane and data plane.

## Why Agbero?

Traditional proxies often rely on static IP-based rules and manual configuration reloads, which break down in modern, dynamic environments. Complex service meshes solve this but introduce massive operational overhead, sidecar injections, and steep learning curves.

Agbero solves these challenges natively:

*   **Encrypted Secret Store (Keeper):** A built-in, passphrase-protected database holds every credential your proxy needs — API keys, TLS certificates, OAuth secrets, passwords. Reference them anywhere in your config with `ss://namespace/key`. Nothing sensitive ever lives as plaintext in a config file.
*   **Identity-Based Rate Limiting:** Stop punishing legitimate users behind corporate NATs. Agbero supports distributed rate limiting and firewalling based on JWT claims, headers, or cookies, synchronized across your cluster via Redis or Gossip.
*   **Centralized Edge Authentication:** Eliminate authentication sprawl. Agbero validates JWTs, handles full OAuth flows (Google, GitHub, OIDC), and integrates with external Forward Auth services directly at the edge.
*   **Zero-Downtime GitOps (Cook):** Deploy static sites and Single Page Applications directly from Git repositories. Agbero pulls, builds isolated deployments, and performs atomic symlink swaps without dropping a single request.
*   **Distributed Cluster Mesh:** No external dependencies required. Agbero nodes automatically discover each other via UDP Gossip and synchronize routing configurations, ACME certificates, and keeper secrets over encrypted streams.
*   **Deep Observability:** Built-in Prometheus and VictoriaMetrics integration provides high-resolution latency histograms and circuit-breaker telemetry without requiring complex log-parsing pipelines.

> **Installation Guide**
> For Installation, see the [Installation Guide](./install.md).

## Core Capabilities

### Traffic Management (L4 & L7)
*   HTTP/1.1, HTTP/2, and HTTP/3 (QUIC) support.
*   TCP Proxying with SNI routing and PROXY Protocol support.
*   Advanced load balancing strategies (Round Robin, Least Conn, Consistent Hash, Adaptive).
*   Automatic Circuit Breaking and Active/Passive Health Probes.
*   Graceful connection draining and hot-reloading.

### Security & WAF
*   Automated Let's Encrypt (HTTP-01) and local development CA (`mkcert`) provisioning.
*   Dynamic Web Application Firewall (WAF) with regex matching, threshold tracking, and auto-banning.
*   Cross-Origin Resource Sharing (CORS) and security header injection.
*   WebAssembly (WASM) middleware support for custom, highly-performant request filtering.

### Content Serving
*   High-performance static file serving with on-the-fly Brotli and Gzip compression.
*   FastCGI support for PHP applications.
*   On-the-fly Markdown to HTML rendering with syntax highlighting.

## Documentation Guide

Navigate through the documentation to master Agbero:

- [**Installation Guide**](./install.md) - Get Agbero running on Linux, macOS, or Windows.
- [**Command Line**](./command.md) - Using Agbero from the command line.
- [**Global Config**](./global.md) - Configure bind addresses, TLS, logging, rate limits, and clustering.
- [**Host Config**](./host.md) - Define routes, backends, auth, and TLS per virtual host.
- [**Serverless Guide**](./serverless.md) - REST proxying, workers, and scheduled tasks without the cloud.
- [**Advanced Guide**](./advance.md) - Deep dive into Clustering, Git Deployments, and Firewall tuning.
- [**Plugin Guide**](./plugin.md) - Write custom high-performance middleware using WebAssembly.
- [**API Reference**](./api.md) - Dynamic route management and Keeper API via the admin API.
- [**Security Guide**](./security.md) - Keeper, secret references, authentication, and TOTP.
- [**Config Reference**](./reference.md) - Complete HCL field reference for all blocks.
- [**Contributor Guide**](./contributor.md) - Architecture overview and guidelines for contributing.
