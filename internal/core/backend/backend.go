package backend

import (
	"context"
	"errors"
	"io"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core"
	"git.imaxinacion.net/aibox/agbero/internal/core/metrics"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/ll"
)

var sharedBufferPool = core.NewBufferPool()

type Backend struct {
	URL          *url.URL
	Proxy        *httputil.ReverseProxy
	Alive        atomic.Bool
	InFlight     atomic.Int64
	Failures     atomic.Int64
	TotalReqs    atomic.Uint64
	Metrics      *metrics.LatencyTracker
	hcConfig     *alaye.HealthCheck
	logger       *ll.Logger
	stop         chan struct{}
	startTime    time.Time
	lastRecovery atomic.Int64 // Unix nano of last time marked alive
	Weight       int          // Added
}

func NewBackend(cfg alaye.Server, route *alaye.Route, logger *ll.Logger) (*Backend, error) {
	u, err := url.Parse(cfg.Address)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	b := &Backend{
		URL:       u,
		Weight:    cfg.Weight, // Store weight
		hcConfig:  route.HealthCheck,
		logger:    logger,
		stop:      make(chan struct{}),
		Metrics:   metrics.NewLatencyTracker(),
		startTime: now,
	}
	b.Alive.Store(true)
	b.lastRecovery.Store(now.UnixNano())

	cbThreshold := 5
	if route.CircuitBreaker != nil && route.CircuitBreaker.Threshold > 0 {
		cbThreshold = route.CircuitBreaker.Threshold
	}

	rp := httputil.NewSingleHostReverseProxy(u)
	rp.Transport = woos.Transport
	rp.FlushInterval = -1
	rp.BufferPool = sharedBufferPool

	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		if !errors.Is(err, context.Canceled) {
			newFailures := b.Failures.Add(1)
			if newFailures >= int64(cbThreshold) {
				if b.Alive.Swap(false) {
					b.logger.Fields("backend", u.Host, "failures", newFailures).Warn("circuit breaker tripped")
				}
			}
		}
		b.logger.Fields("upstream", u.Host, "err", err).Error("upstream proxy error")
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	origDirector := rp.Director
	rp.Director = func(req *http.Request) {
		origDirector(req)
		req.Host = u.Host
		req.Header.Set("X-Forwarded-Host", req.Host)
		req.Header.Set("X-Forwarded-Proto", req.URL.Scheme)
		req.Header.Del("Keep-Alive")
		req.Header.Del("Proxy-Authenticate")
		req.Header.Del("Proxy-Authorization")
		req.Header.Del("Te")
		req.Header.Del("Trailers")
		req.Header.Del("Transfer-Encoding")
	}

	b.Proxy = rp

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

	dur := time.Since(start).Microseconds()
	b.Metrics.Record(dur)

	b.TotalReqs.Add(1)
}

func (b *Backend) Stop() {
	close(b.stop)
}

func (b *Backend) healthCheckLoop() {
	interval := 10 * time.Second
	if b.hcConfig.Interval != 0 {
		interval = b.hcConfig.Interval

	}

	timeout := 5 * time.Second
	if b.hcConfig.Timeout != 0 {
		timeout = b.hcConfig.Timeout
	}

	threshold := 3
	if b.hcConfig.Threshold > 0 {
		threshold = b.hcConfig.Threshold
	}

	// Add initial jitter to desync checks
	jitter := time.Duration(rand.Int63n(int64(interval) / 2)) // 0-50% jitter
	time.Sleep(jitter)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

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
			resp, err := client.Get(targetURL)
			healthy := err == nil && resp != nil && resp.StatusCode >= 200 && resp.StatusCode < 500

			if resp != nil && resp.Body != nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}

			if healthy {
				b.Failures.Store(0)

				consecutiveFailures = 0
				if !b.Alive.Load() {
					now := time.Now().UnixNano()
					b.Alive.Store(true)
					b.lastRecovery.Store(now)
					b.logger.Fields("backend", b.URL.Host).Info("backend recovered/UP")
				}
			} else {
				consecutiveFailures++
				if consecutiveFailures >= threshold && b.Alive.Load() {
					b.Alive.Store(false)
					b.logger.Fields("backend", b.URL.Host, "err", err).Warn("backend health check failed")
				}
			}

			// Add jitter to next tick (reset ticker for variance)
			jitter = time.Duration(rand.Int63n(int64(interval) / 2))
			ticker.Reset(interval + jitter)
		}
	}
}

// Uptime returns time since backend creation
func (b *Backend) Uptime() time.Duration {
	return time.Since(b.startTime)
}

// LastRecovery returns time of last recovery to alive state
func (b *Backend) LastRecovery() time.Time {
	return time.Unix(0, b.lastRecovery.Load())
}
