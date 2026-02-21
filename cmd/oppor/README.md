# Oppor - Load Balancer Testing Tool

Oppor is a production-grade load tester and test server designed specifically for evaluating load balancers, API gateways, and proxy servers. It simulates realistic traffic patterns, failures, and resource usage to help identify balancing issues, session stickiness problems, and performance bottlenecks.

Key features:
- **Load Testing**: Concurrent requests with rate limiting, custom headers, bodies, and methods.
- **Test Server**: Simulates variable latency, failures, CPU/memory load, caching, sessions, and TLS.
- **Metrics**: Detailed latency histograms, error classification, status codes, and timeseries data.
- **Interactive Mode**: Prompt-based configuration for quick testing.
- **Exports**: JSON summaries and CSV timeseries for analysis.
- **Multi-Server**: Run multiple instances on port ranges for cluster simulation.

Version: 3.0.0

## Installation

### From Source
Requires Go 1.21+.
```bash
go install github.com/your-repo/oppor@latest
```

### Binary Releases
Download pre-built binaries from the repository releases page for your platform (Linux, macOS, Windows).

Verify installation:
```bash
oppor --version
```

## Global Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-i, --interactive` | Enable interactive mode for guided configuration | `false` |
| `--version` | Show version information | N/A |
| `--help` | Show help | N/A |

## Commands

### 🚀 `run` - Perform Load Test
Run a load test against specified targets.

**Usage:**
```bash
oppor run [flags]
```

**Flags:**
- `-t, --target`: Target URLs (comma-separated or repeated) (required)
- `-c, --concurrency`: Number of concurrent workers (default: 10)
- `-n, --requests`: Total requests to send (0 = infinite) (default: 0)
- `-d, --duration`: Test duration (e.g., 30s, 5m)
- `-r, --rate`: Requests per second limit (0 = unlimited) (default: 0)
- `-X, --method`: HTTP method (default: GET)
- `-H, --header`: Custom headers (Key:Value, repeatable)
- `-b, --body`: Request body
- `--timeout`: Request timeout (e.g., 30s) (default: 30s)

**Behavior:**
- Distributes requests across targets.
- Collects metrics: requests, successes, errors, latency percentiles (P50/P95/P99), RPS, bytes transferred.
- Classifies errors (timeout, connection refused, DNS, TLS, reset, other).
- Exports results to JSON and CSV automatically with timestamp.

**Validation:**
- At least one target required.
- Targets must start with http:// or https://.
- Concurrency > 0.
- Requests >= 0.

### 🖥️ `serve` - Start Test Server(s)
Run one or more test servers with simulated behaviors.

**Usage:**
```bash
oppor serve [flags]
```

**Flags:**
- `-p, --port`: Single port to listen on (default: 8080)
- `-r, --range`: Port range (e.g., 8000-8010)
- `-s, --speed`: Speed profile (fast, normal, slow, erratic)
- `-l, --latency`: Base latency (e.g., 5ms)
- `-j, --jitter`: Latency jitter (e.g., 10ms)
- `-f, --failure-rate`: Failure rate (0.0-1.0) (default: 0)
- `-fc, --failure-codes`: Comma-separated failure codes (e.g., 500,503) (default: 500,502,503,504)
- `-fp, --failure-pattern`: Failure pattern (random, periodic, burst) (default: random)
- `-c, --content-mode`: Response mode (static, dynamic, streaming) (default: static)
- `-b, --body-size`: Response body size (1KB, 10KB, 100KB, 1MB, 10MB)
- `--slow-endpoint`: Path for slow responses (e.g., /slow/*)
- `--cpu-load`: CPU load simulation (0.0-1.0) (default: 0)
- `--memory-per-req`: Memory MB per request (default: 0)
- `--session-mode`: Session handling (none, sticky) (default: none)
- `--cache-hit-rate`: Cache hit simulation rate (0.0-1.0) (default: 0)
- `--tls-cert`: TLS certificate file
- `--tls-key`: TLS key file

**Behavior:**
- Listens on specified port(s).
- Simulates failures, latency, CPU/memory usage, caching, and sessions.
- Endpoints:
    - `/`: Main handler with simulations.
    - `/health`: Health check (JSON).
    - `/ready`: Readiness probe.
    - `/metrics`: Server metrics (JSON).
    - `/stats`: Runtime stats (JSON).
    - `/debug/pprof/*`: Profiling endpoints.
- Headers added: X-Server-Port, X-Request-Count, X-Response-Latency, X-Server-Time, X-Cache.
- Graceful shutdown on Ctrl+C.

**Validation:**
- Failure rate, cache hit rate, CPU load: 0.0-1.0.

### Interactive Mode
Use `-i` for prompt-based setup.
- Choose mode: Load Test or Server.
- For Load Test: Input targets, concurrency, requests, duration, rate limit.
- For Server: Input port, speed profile, failure rate.
- Defaults applied where possible.

## Examples

### Basic Load Test
```bash
# Test two targets with 20 workers, 1000 requests
oppor run -t http://localhost:8080 -t http://localhost:8081 -c 20 -n 1000
```

### Rate-Limited Test with Headers
```bash
oppor run -t https://api.example.com -c 50 -d 1m -r 100 -X POST -H "Authorization: Bearer token" -b '{"key":"value"}'
```

### Start Multiple Servers
```bash
# Run servers on ports 8000-8002 with 10% failure rate
oppor serve -r 8000-8002 -f 0.1 -fp burst
```

### Simulate Slow API
```bash
oppor serve -p 8080 -s slow --slow-endpoint /api/slow/* --cpu-load 0.5 --memory-per-req 10 --tls-cert cert.pem --tls-key key.pem
```

### Interactive Load Test
```bash
oppor -i
# Follow prompts to configure and run
```

## Output

### Load Test Summary
Printed to console:
- Configuration details.
- Requests: Total, successful, errors, RPS.
- Latency: Avg, P50, P95, P99, Std Dev (ms).
- Data: Total bytes.
- Status codes distribution.
- Error types breakdown.

Exported files:
- `loadtest-<timestamp>.json`: Full results including config and timeseries.
- `loadtest-<timestamp>.csv`: Per-second metrics (timestamp, requests, errors, bytes, rps).

### Server Metrics
Access via `/metrics` endpoint (JSON):
- Port, requests, active connections, uptime, memory used, avg/p99 latency, error rate, timestamp.

## Troubleshooting

- **Invalid Targets:** Ensure URLs start with http(s)://.
- **Port Conflicts:** Check for occupied ports with `netstat` or `lsof`.
- **High Memory/CPU:** Adjust simulation flags; monitor with `/stats`.
- **TLS Errors:** Verify cert/key files; use self-signed for testing.
- **Infinite Test:** Use -n or -d to limit; Ctrl+C to stop.
- **No Output:** Increase verbosity by checking code logs (add fmt.Printf for debugging).

## Development

- Dependencies: flaggy, huh, lipgloss, hdrhistogram-go, golang.org/x/time/rate.
- Build: `go build -o oppor`.
- Test: Add unit tests for configs, metrics, and handlers.
- Contribute: Fork and PR with features like graphing or Prometheus export.

For issues, report on the repository.