// internal/core/backend.go
package core

import (
	"context"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
)

// Backend represents a single upstream server with state.
// It replaces the old simple 'backendTarget'.
type Backend struct {
	URL   *url.URL
	Proxy *httputil.ReverseProxy

	// Atomic State (High performance, no mutex on hot path)
	Alive     atomic.Bool   // Is backend healthy?
	InFlight  atomic.Int64  // Current active requests
	Failures  atomic.Int64  // Consecutive failure count (for circuit breaker)
	TotalReqs atomic.Uint64 // Total requests served
	Latency   atomic.Int64  // Moving average latency in microseconds

	// Internals
	hcConfig *woos.HealthCheckConfig
	logger   anyLogger
	stop     chan struct{} // To stop health check loop
}

func NewBackend(targetStr string, route *woos.Route, logger anyLogger) (*Backend, error) {
	u, err := url.Parse(targetStr)
	if err != nil {
		return nil, err
	}

	b := &Backend{
		URL:      u,
		hcConfig: route.HealthCheck,
		logger:   logger,
		stop:     make(chan struct{}),
	}

	// Default to alive. If health checks are enabled, they will correct this shortly.
	b.Alive.Store(true)

	// Setup Proxy
	rp := httputil.NewSingleHostReverseProxy(u)
	rp.Transport = woos.SharedTransport
	rp.FlushInterval = -1 // Essential for streaming (SSE)

	// Custom Error Handler
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		// Context canceled is common (client disconnect), don't count as backend failure
		if err != context.Canceled {
			b.Failures.Add(1)
		}
		b.logger.Fields("upstream", u.Host, "err", err).Error("upstream proxy error")
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	// Director: We DO NOT strip Connection/Upgrade headers anymore to support WebSockets natively
	origDirector := rp.Director
	rp.Director = func(req *http.Request) {
		origDirector(req)
		req.Host = u.Host

		// Set standard proxy headers
		// Note: X-Forwarded-For is handled by the upstream Director implementation usually,
		// but we ensure IP middleware has set RemoteAddr correctly.
		req.Header.Set("X-Forwarded-Host", req.Host)
		req.Header.Set("X-Forwarded-Proto", req.URL.Scheme)

		// CLEANUP: We remove standard hop-by-hop, BUT we must keep Upgrade/Connection
		// for Websockets to work via httputil default behavior.
		req.Header.Del("Keep-Alive")
		req.Header.Del("Proxy-Authenticate")
		req.Header.Del("Proxy-Authorization")
		req.Header.Del("Te")
		req.Header.Del("Trailers")
		req.Header.Del("Transfer-Encoding")
	}

	b.Proxy = rp

	// Start Health Check Loop if configured
	if b.hcConfig != nil && b.hcConfig.Path != "" {
		go b.healthCheckLoop()
	}

	return b, nil
}

func (b *Backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	b.InFlight.Add(1)
	defer b.InFlight.Add(-1)

	b.Proxy.ServeHTTP(w, r)

	// Simple Moving Average for Latency (approximate)
	// We use integer microseconds to avoid float overhead on atomic
	dur := time.Since(start).Microseconds()
	old := b.Latency.Load()
	if old == 0 {
		b.Latency.Store(dur)
	} else {
		// Weight new sample 20%
		newLat := int64((float64(old) * 0.8) + (float64(dur) * 0.2))
		b.Latency.Store(newLat)
	}
	b.TotalReqs.Add(1)
}

func (b *Backend) Stop() {
	close(b.stop)
}

func (b *Backend) healthCheckLoop() {
	// Parse settings with defaults
	interval := 10 * time.Second
	if b.hcConfig.Interval != "" {
		if d, err := time.ParseDuration(b.hcConfig.Interval); err == nil {
			interval = d
		}
	}

	timeout := 5 * time.Second
	if b.hcConfig.Timeout != "" {
		if d, err := time.ParseDuration(b.hcConfig.Timeout); err == nil {
			timeout = d
		}
	}

	threshold := 3
	if b.hcConfig.Threshold > 0 {
		threshold = b.hcConfig.Threshold
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Dedicated client for health checks (disable keepalives to test full connection)
	client := &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{DisableKeepAlives: true},
	}

	// Pre-calculate URL
	targetURL := b.URL.ResolveReference(&url.URL{Path: b.hcConfig.Path}).String()
	consecutiveFailures := 0

	for {
		select {
		case <-b.stop:
			return
		case <-ticker.C:
			// Perform Check
			resp, err := client.Get(targetURL)
			healthy := err == nil && resp.StatusCode >= 200 && resp.StatusCode < 500

			if resp != nil {
				// Drain and close to reuse connection if we enabled keepalives,
				// but here just for cleanup.
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}

			if healthy {
				consecutiveFailures = 0
				if !b.Alive.Load() {
					b.Alive.Store(true)
					b.logger.Fields("backend", b.URL.Host).Info("backend marked UP")
				}
			} else {
				consecutiveFailures++
				if consecutiveFailures >= threshold && b.Alive.Load() {
					b.Alive.Store(false)
					b.logger.Fields("backend", b.URL.Host).Warn("backend marked DOWN")
				}
			}
		}
	}
}
