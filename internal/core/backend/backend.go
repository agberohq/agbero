// internal/core/backend/backend.go
package backend

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core"
	"git.imaxinacion.net/aibox/agbero/internal/core/metrics"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
)

var sharedBufferPool = core.NewBufferPool()

type Backend struct {
	URL       *url.URL
	Proxy     *httputil.ReverseProxy
	Alive     atomic.Bool
	InFlight  atomic.Int64
	Failures  atomic.Int64
	TotalReqs atomic.Uint64
	Metrics   *metrics.LatencyTracker
	hcConfig  *woos.HealthCheckConfig
	logger    woos.TlsLogger
	stop      chan struct{}
}

func NewBackend(targetStr string, route *woos.Route, logger woos.TlsLogger) (*Backend, error) {
	u, err := url.Parse(targetStr)
	if err != nil {
		return nil, err
	}

	b := &Backend{
		URL:      u,
		hcConfig: route.HealthCheck,
		logger:   logger,
		stop:     make(chan struct{}),
		Metrics:  metrics.NewLatencyTracker(),
	}

	b.Alive.Store(true)

	cbThreshold := 5
	if route.CircuitBreaker != nil && route.CircuitBreaker.Threshold > 0 {
		cbThreshold = route.CircuitBreaker.Threshold
	}

	rp := httputil.NewSingleHostReverseProxy(u)
	rp.Transport = woos.SharedTransport
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
			healthy := err == nil && resp.StatusCode >= 200 && resp.StatusCode < 500

			if resp != nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}

			if healthy {
				b.Failures.Store(0)

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
