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

	// Default to alive.
	b.Alive.Store(true)

	// Circuit Breaker Threshold
	cbThreshold := 5
	if route.CircuitBreaker != nil && route.CircuitBreaker.Threshold > 0 {
		cbThreshold = route.CircuitBreaker.Threshold
	}

	// Setup Proxy
	rp := httputil.NewSingleHostReverseProxy(u)
	rp.Transport = woos.SharedTransport
	rp.FlushInterval = -1 // Essential for streaming (SSE)

	// Custom Error Handler for Circuit Breaker
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		// Context canceled is common (client disconnect), don't count as backend failure
		// unless we want to be very strict.
		if err != context.Canceled {
			newFailures := b.Failures.Add(1)

			// TRIP THE CIRCUIT
			if newFailures >= int64(cbThreshold) {
				if b.Alive.Swap(false) {
					b.logger.Fields("backend", u.Host, "failures", newFailures).Warn("circuit breaker tripped")
				}
			}
		}

		b.logger.Fields("upstream", u.Host, "err", err).Error("upstream proxy error")
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	// Director: Support WebSockets natively by NOT stripping Connection/Upgrade
	origDirector := rp.Director
	rp.Director = func(req *http.Request) {
		origDirector(req)
		req.Host = u.Host

		req.Header.Set("X-Forwarded-Host", req.Host)
		req.Header.Set("X-Forwarded-Proto", req.URL.Scheme)

		// Remove standard hop-by-hop headers
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

	targetURL := b.URL.ResolveReference(&url.URL{Path: b.hcConfig.Path}).String()
	consecutiveFailures := 0

	for {
		select {
		case <-b.stop:
			return
		case <-ticker.C:
			// Perform Check
			resp, err := client.Get(targetURL)
			// Status < 500 is usually considered "reachable"
			healthy := err == nil && resp.StatusCode >= 200 && resp.StatusCode < 500

			if resp != nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}

			if healthy {
				// RECOVERY logic
				b.Failures.Store(0) // Reset circuit breaker count

				consecutiveFailures = 0
				if !b.Alive.Load() {
					b.Alive.Store(true)
					b.logger.Fields("backend", b.URL.Host).Info("backend recovered/UP")
				}
			} else {
				consecutiveFailures++
				if consecutiveFailures >= threshold && b.Alive.Load() {
					b.Alive.Store(false)
					b.logger.Fields("backend", b.URL.Host).Warn("backend health check failed")
				}
			}
		}
	}
}
