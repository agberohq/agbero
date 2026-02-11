package backend

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core"
	"git.imaxinacion.net/aibox/agbero/internal/core/metrics"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/errors"
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
	lastRecovery atomic.Int64
	Weight       int
	Cond         *Conditions
	rnd          *rand.Rand
	stopOnce     sync.Once
}

func NewBackend(cfg alaye.Server, route *alaye.Route, logger *ll.Logger) (*Backend, error) {
	u, err := url.Parse(cfg.Address)
	if err != nil {
		return nil, err
	}

	if u.Scheme == "" {
		return nil, errors.Newf("%w :(http or https)", woos.ErrBackendMissingScheme)
	}
	if u.Host == "" {
		return nil, woos.ErrBackendMissingHost
	}
	switch u.Scheme {
	case woos.Http, woos.Https:
		// ok
	default:
		return nil, fmt.Errorf("%w: %q", woos.ErrBackendBadScheme, u.Scheme)
	}

	cond, err := NewConditions(cfg.Conditions)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	b := &Backend{
		URL:       u,
		Weight:    cfg.Weight,
		Cond:      cond,
		hcConfig:  route.HealthCheck,
		logger:    logger,
		stop:      make(chan struct{}),
		Metrics:   metrics.NewLatencyTracker(),
		startTime: now,
	}
	b.Alive.Store(true)
	b.lastRecovery.Store(now.UnixNano())

	cbThreshold := woos.DefaultCircuitBreakerThreshold
	if route.CircuitBreaker != nil && route.CircuitBreaker.Threshold > 0 {
		cbThreshold = route.CircuitBreaker.Threshold
	}

	rp := httputil.NewSingleHostReverseProxy(u)
	rp.BufferPool = sharedBufferPool

	// Clone transport and explicitly disable ExpectContinueTimeout.
	t := woos.Transport.Clone()
	t.ExpectContinueTimeout = 0

	// Ensure we don't carry over unlimited flushes unless streaming
	rp.FlushInterval = -1

	if cfg.Streaming.Enabled {
		t.ResponseHeaderTimeout = 0
		rp.FlushInterval = cfg.Streaming.EffectiveFlushInterval()
	}
	rp.Transport = t

	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		if errors.Is(err, context.Canceled) {
			return
		}

		// Trip Circuit Breaker
		newFailures := b.Failures.Add(1)
		if newFailures >= int64(cbThreshold) {
			if b.Alive.Swap(false) {
				b.logger.Fields("backend", u.Host, "failures", newFailures).Warn("circuit breaker tripped")
			}
		}

		// gRPC-aware Error Handling
		if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Grpc-Status", "14") // 14 = UNAVAILABLE
			w.Header().Set("Grpc-Message", "upstream backend unavailable")
			w.WriteHeader(http.StatusOK)
			return
		}

		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	origDirector := rp.Director
	rp.Director = func(req *http.Request) {
		origDirector(req)
		originalHost := req.Host
		req.Host = b.URL.Host

		proto := woos.Http
		if req.TLS != nil {
			proto = woos.Https
		}

		req.Header.Set(woos.HeaderXForwardedHost, originalHost)
		req.Header.Set(woos.HeaderXForwardedProto, proto)
		req.Header.Set(woos.HeaderXForwardedServer, woos.Name)
		req.Header.Add(woos.HeaderVia, fmt.Sprintf("1.1 %s", woos.Name))
	}

	b.Proxy = rp

	// FIX: Initialize RNG here, BEFORE starting the health check loop to avoid data race
	b.rnd = rand.New(rand.NewSource(time.Now().UnixNano()))

	if b.hcConfig != nil && b.hcConfig.Path != "" {
		go b.healthCheckLoop()
	}

	return b, nil
}

// Jitter returns a random duration to avoid thundering herd.
// The lazy init check is removed as NewBackend guarantees initialization.
func (b *Backend) Jitter(interval time.Duration) time.Duration {
	return time.Duration(b.rnd.Int63n(int64(interval / woos.HealthCheckJitterFraction)))
}

func (b *Backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !b.Alive.Load() {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	b.InFlight.Add(1)
	defer b.InFlight.Add(-1)

	start := time.Now()

	b.Proxy.ServeHTTP(w, r)

	dur := time.Since(start).Microseconds()
	b.Metrics.Record(dur)
	b.TotalReqs.Add(1)
}

func (b *Backend) Stop() {
	b.stopOnce.Do(func() {
		close(b.stop)
		b.Metrics.Close() // Ensure metrics routines are cleaned up
	})
}

func (b *Backend) healthCheckLoop() {
	interval := woos.DefaultHealthCheckInterval
	if b.hcConfig.Interval > 0 {
		interval = b.hcConfig.Interval
	}

	timeout := woos.DefaultHealthCheckTimeout
	if b.hcConfig.Timeout > 0 {
		timeout = b.hcConfig.Timeout
	}

	threshold := woos.DefaultHealthCheckThreshold
	if b.hcConfig.Threshold > 0 {
		threshold = b.hcConfig.Threshold
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			MaxIdleConnsPerHost: woos.DefaultMaxIdleConnsPerHost,
			DisableKeepAlives:   true, // Active checks should not hog connections
		},
	}

	targetURL := b.URL.ResolveReference(
		&url.URL{Path: b.hcConfig.Path},
	).String()

	failures := 0
	timer := time.NewTimer(b.Jitter(interval))
	defer timer.Stop()

	for {
		select {
		case <-b.stop:
			return
		case <-timer.C:
			resp, err := client.Get(targetURL)
			healthy := err == nil && resp != nil && resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusBadRequest

			if resp != nil && resp.Body != nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}

			if healthy {
				failures = 0
				b.Failures.Store(0)
				if !b.Alive.Load() {
					now := time.Now().UnixNano()
					b.Alive.Store(true)
					b.lastRecovery.Store(now)
				}
			} else {
				failures++
				if failures >= threshold && b.Alive.Load() {
					b.Alive.Store(false)
				}
			}

			timer.Reset(interval + b.Jitter(interval))
		}
	}
}

func (b *Backend) Uptime() time.Duration {
	return time.Since(b.startTime)
}

func (b *Backend) LastRecovery() time.Time {
	return time.Unix(0, b.lastRecovery.Load())
}

//func (b *Backend) Jitter(interval time.Duration) time.Duration {
//	if b.rnd == nil {
//		b.rnd = rand.New(rand.NewSource(time.Now().UnixNano()))
//	}
//	return time.Duration(b.rnd.Int63n(int64(interval / woos.HealthCheckJitterFraction)))
//}
