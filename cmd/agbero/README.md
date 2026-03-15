# Agbero CLI Reference

Agbero is a modern, high-performance reverse proxy, load balancer, and API gateway built in Go. It combines the power of a full-featured proxy server with built-in security, scalability, and ease of use.

## Key Capabilities

- **HTTP/HTTPS Proxying** - Route and manage web traffic with advanced load balancing
- **TCP Proxying** - Handle raw TCP connections for databases, message queues, and custom protocols
- **Static File Serving** - Serve static assets directly with configurable caching and compression
- **Security Features** - Built-in firewall rules, rate limiting, and request filtering
- **Automatic TLS** - Seamless Let's Encrypt integration for automated SSL certificate management
- **Horizontal Scaling** - Distributed clustering via gossip protocol for high availability

## Configuration

Agbero uses HCL (HashiCorp Configuration Language) for clean, human-readable configurations that are both powerful and intuitive. Configuration examples and syntax details are available in the [configuration guide](../../docs/global.md).

## CLI Documentation

For detailed information about individual commands, command-line options, and usage examples, please refer to the comprehensive [command reference](../../docs/command.md). This document covers:

- Installation and basic usage
- Command syntax and available options
- Configuration management
- Server control commands
- Debugging and monitoring tools
- Common workflows and examples

The command reference provides everything you need to effectively manage your Agbero instances from the command line.