## Welcome to the documentation!

## Why Agbero? Solving Real Problems

### The Problem with Traditional Proxies

Traditional proxies like Nginx and Caddy often fall short in modern microservices environments:

1. **Static Configuration**: Most require manual reloads and restarts for service discovery
2. **Complex Service Discovery**: Integrating with service meshes requires plugins and extra tooling
3. **Poor Developer Experience**: Local development TLS setup is cumbersome
4. **Limited Observability**: Basic metrics without detailed latency histograms
5. **No Built-in Gossip**: Manual coordination for multi-node setups

### How Agbero Solves These Issues

> *As referenced in [this Twitter thread](https://x.com/ayushagarwal/status/2016439436192751948?s=46), developers need tools that bridge local development and production seamlessly.*

**Agbero provides**:  
✅ Zero-config local development with auto-TLS  
✅ Production-grade load balancing with zero-downtime updates  
✅ Built-in gossip for automatic service discovery  
✅ Unified configuration from development to production


- [API Reference](./guide.md) - Complete configuration reference
- [Examples](./install.md) - More real-world scenarios
- [Contributing](./plugin.md) - How to extend Agbero