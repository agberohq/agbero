package xhttp

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

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"git.imaxinacion.net/aibox/agbero/internal/core/zulu"
	metrics2 "git.imaxinacion.net/aibox/agbero/internal/pkg/metrics"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/ll"
)

var sharedBufferPool = zulu.NewBufferPool()

var hopHeaders = []string{
	woos.HeaderKeyConnection,
	woos.HeaderKeepAlive,
	woos.HeaderProxyAuthenticate,
	woos.HeaderProxyAuthorization,
	woos.HeaderTE,
	woos.HeaderTrailers,
	woos.HeaderTransferEncoding,
	woos.HeaderKeyUpgrade,
}

type Backend struct {
	URL          *url.URL
	Proxy        *httputil.ReverseProxy
	Alive        *atomic.Bool
	stop         chan struct{}
	stopOnce     sync.Once
	startTime    time.Time
	lastRecovery atomic.Int64
	Weight       int
	Cond         *Conditions
	rnd          *rand.Rand
	logger       *ll.Logger

	Health   *metrics2.Health
	Activity *metrics2.Activity

	hcConfig *alaye.HealthCheck
}

func NewBackend(cfg alaye.Server, route *alaye.Route, logger *ll.Logger, registry *metrics2.Registry) (*Backend, error) {
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
	default:
		return nil, fmt.Errorf("%w: %q", woos.ErrBackendBadScheme, u.Scheme)
	}

	cond, err := NewConditions(cfg.Criteria)
	if err != nil {
		return nil, err
	}

	if registry == nil {
		registry = metrics2.DefaultRegistry
	}

	statsKey := fmt.Sprintf("%s|%s", route.Key(), cfg.Address)
	stats := registry.GetOrRegister(statsKey)

	now := time.Now()
	b := &Backend{
		URL:          u,
		Weight:       cfg.Weight,
		Cond:         cond,
		hcConfig:     &route.HealthCheck,
		logger:       logger,
		stop:         make(chan struct{}),
		startTime:    now,
		lastRecovery: atomic.Int64{},
		Health:       stats.Health,
		Activity:     stats.Activity,
		Alive:        stats.Alive,
	}

	b.lastRecovery.Store(now.UnixNano())

	cbThreshold := woos.DefaultCircuitBreakerThreshold
	if route != nil && route.CircuitBreaker.Threshold > 0 {
		cbThreshold = route.CircuitBreaker.Threshold
	}

	rp := httputil.NewSingleHostReverseProxy(u)
	rp.BufferPool = sharedBufferPool

	t := woos.Transport.Clone()
	t.ExpectContinueTimeout = 0

	if cfg.Streaming.Enabled.Active() {
		t.ResponseHeaderTimeout = 0
		rp.FlushInterval = cfg.Streaming.EffectiveFlushInterval()
		if rp.FlushInterval <= 0 {
			rp.FlushInterval = 100 * time.Millisecond
		}
	} else {
		rp.FlushInterval = 0
	}

	rp.Transport = t
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		if errors.Is(err, context.Canceled) {
			return
		}

		newFailures := b.Activity.Failures.Add(1)

		if newFailures >= uint64(cbThreshold) && b.Alive.Swap(false) {
			b.logger.Fields("backend", u.Host, "failures", newFailures).Warn("circuit breaker tripped")
		}

		if !b.Alive.Load() && time.Since(b.LastRecovery()) > 5*time.Second {
			b.Activity.Failures.Store(0)
		}

		if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Grpc-Status", "14")
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

		for _, h := range hopHeaders {
			req.Header.Del(h)
		}

		proto := woos.Http
		if req.TLS != nil {
			proto = woos.Https
		}

		req.Header.Set(woos.HeaderXForwardedHost, originalHost)
		req.Header.Set(woos.HeaderXForwardedProto, proto)
		req.Header.Set(woos.HeaderXForwardedServer, woos.Name)
		if port, ok := req.Context().Value(woos.CtxPort).(string); ok {
			req.Header.Set("X-Forwarded-Port", port)
		}
		req.Header.Add(woos.HeaderVia, fmt.Sprintf("1.1 %s", woos.Name))
	}

	b.Proxy = rp
	b.rnd = rand.New(rand.NewSource(time.Now().UnixNano()))

	if b.hcConfig != nil && b.hcConfig.Path != "" {
		go b.healthCheckLoop()
	}

	return b, nil
}

func (b *Backend) Jitter(interval time.Duration) time.Duration {
	return time.Duration(b.rnd.Int63n(int64(interval / woos.HealthCheckJitterFraction)))
}

func (b *Backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !b.Alive.Load() {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	start := time.Now()
	b.Activity.StartRequest()
	defer func() {
		dur := time.Since(start).Microseconds()
		b.Activity.EndRequest(dur, false)
	}()

	b.Proxy.ServeHTTP(w, r)
}

func (b *Backend) Stop() {
	b.stopOnce.Do(func() {
		close(b.stop)
	})
}

func (b *Backend) healthCheckLoop() {
	if b.hcConfig == nil {
		return
	}

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

	cbThreshold := woos.DefaultCircuitBreakerThreshold
	if b.hcConfig != nil {
		if route := b.hcConfig; route.Threshold > 0 {
			cbThreshold = route.Threshold
		}
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			MaxIdleConnsPerHost: woos.DefaultMaxIdleConnsPerHost,
			DisableKeepAlives:   true,
		},
	}

	targetURL := b.URL.ResolveReference(&url.URL{Path: b.hcConfig.Path}).String()
	failures := int64(0)
	timer := time.NewTimer(b.Jitter(interval))
	defer timer.Stop()

	for {
		select {
		case <-b.stop:
			return
		case <-timer.C:
			resp, err := client.Get(targetURL)
			healthy := err == nil && resp != nil &&
				resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusBadRequest

			if resp != nil && resp.Body != nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}

			if healthy {
				failures = 0
				b.Health.RecordSuccess()
				b.Activity.Failures.Store(0)
				if !b.Alive.Load() {
					b.Alive.Store(true)
					b.lastRecovery.Store(time.Now().UnixNano())
					b.logger.Fields("backend", b.URL.Host).Info("backend recovered")
				}
			} else {
				failures++
				b.Health.RecordFailure()
				newFailures := b.Activity.Failures.Add(1)
				if failures >= int64(threshold) || newFailures >= uint64(cbThreshold) {
					if b.Alive.Swap(false) {
						b.logger.Fields("backend", b.URL.Host, "failures", failures).Warn("circuit breaker tripped")
					}
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
