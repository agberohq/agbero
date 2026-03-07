package xhttp

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/lb"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/metrics"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/ll"
)

type BackendState int32

const (
	StateActive BackendState = iota
	StateDraining
	StateDead
)

type Backend struct {
	URL   *url.URL
	Proxy *httputil.ReverseProxy

	// alive indicates health check status (Up/Down)
	alive atomic.Bool

	// state indicates lifecycle (Active/Draining/Dead)
	state atomic.Int32

	stop         chan struct{}
	stopOnce     sync.Once
	startTime    time.Time
	lastRecovery atomic.Int64
	weight       int
	Cond         *Conditions
	rnd          *rand.Rand
	logger       *ll.Logger

	Health   *metrics.Health
	Activity *metrics.Activity

	hcConfig     *alaye.HealthCheck
	routeDomains []string
	Fallback     http.Handler
}

func NewBackend(cfg alaye.Server, xhttpCfg ConfigBackend) (*Backend, error) {
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
	route := xhttpCfg.Route
	if route == nil {
		route = &alaye.Route{}
	}
	logger := xhttpCfg.Logger
	if logger == nil {
		logger = ll.New("backend").Disable()
	}
	registry := xhttpCfg.Registry
	if registry == nil {
		registry = metrics.DefaultRegistry
	}
	statsKey := fmt.Sprintf("%s|%s", route.Key(), cfg.Address)
	stats := registry.GetOrRegister(statsKey)
	now := time.Now()
	b := &Backend{
		URL:          u,
		weight:       cfg.Weight,
		Cond:         cond,
		hcConfig:     &route.HealthCheck,
		logger:       logger,
		stop:         make(chan struct{}),
		startTime:    now,
		lastRecovery: atomic.Int64{},
		Health:       stats.Health,
		Activity:     stats.Activity,
		Fallback:     xhttpCfg.Fallback,
	}
	b.alive.Store(true)
	b.state.Store(int32(StateActive))
	b.lastRecovery.Store(now.UnixNano())

	cbThreshold := woos.DefaultCircuitBreakerThreshold
	if cbThreshold == 0 {
		cbThreshold = 5
	}
	if route.CircuitBreaker.Threshold > 0 {
		cbThreshold = route.CircuitBreaker.Threshold
	}

	if len(xhttpCfg.Domains) > 0 {
		b.routeDomains = make([]string, len(xhttpCfg.Domains))
		copy(b.routeDomains, xhttpCfg.Domains)
	}

	rp := &httputil.ReverseProxy{}

	t := woos.Transport.Clone()
	t.Proxy = nil // Explicitly disable proxy to prevent environment interference
	t.ExpectContinueTimeout = 0
	if cfg.Streaming.Enabled.Active() {
		t.ResponseHeaderTimeout = 0
		rp.FlushInterval = cfg.Streaming.EffectiveFlushInterval()
		if rp.FlushInterval <= 0 {
			rp.FlushInterval = -1
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

		if cbThreshold > 0 && newFailures >= uint64(cbThreshold) && b.alive.Swap(false) {
			b.logger.Fields("backend", u.Host, "failures", newFailures).Warn("circuit breaker tripped")
		}
		if !b.alive.Load() && time.Since(b.LastRecovery()) > 5*time.Second {
			b.Activity.Failures.Store(0)
		}
		if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Grpc-Status", "14")
			w.Header().Set("Grpc-Message", "upstream backend unavailable")
			w.WriteHeader(http.StatusOK)
			return
		}
		if b.Fallback != nil {
			b.Fallback.ServeHTTP(w, r)
			return
		}
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	rp.Rewrite = func(pr *httputil.ProxyRequest) {
		pr.Out.URL.Scheme = u.Scheme
		pr.Out.URL.Host = u.Host
		pr.Out.URL.User = u.User
		apath := u.EscapedPath()
		bpath := pr.In.URL.EscapedPath()
		aslash := strings.HasSuffix(apath, "/")
		bslash := strings.HasPrefix(bpath, "/")
		switch {
		case aslash && bslash:
			pr.Out.URL.Path = u.Path + pr.In.URL.Path[1:]
			pr.Out.URL.RawPath = apath + bpath[1:]
		case !aslash && !bslash:
			pr.Out.URL.Path = u.Path + "/" + pr.In.URL.Path
			pr.Out.URL.RawPath = apath + "/" + bpath
		default:
			pr.Out.URL.Path = u.Path + pr.In.URL.Path
			pr.Out.URL.RawPath = apath + bpath
		}
		targetQuery := u.RawQuery
		inQuery := pr.In.URL.RawQuery
		if targetQuery == "" || inQuery == "" {
			pr.Out.URL.RawQuery = targetQuery + inQuery
		} else {
			pr.Out.URL.RawQuery = targetQuery + "&" + inQuery
		}
		if _, ok := pr.Out.Header["User-Agent"]; !ok {
			pr.Out.Header.Set("User-Agent", "")
		}

		pr.Out.Host = u.Host

		pr.SetXForwarded()
		for _, h := range hopHeaders {
			pr.Out.Header.Del(h)
		}
		proto := woos.Http

		if pr.In.TLS != nil {
			proto = woos.Https
		}
		pr.Out.Header.Set(woos.HeaderXForwardedHost, pr.In.Host)
		pr.Out.Header.Set(woos.HeaderXForwardedProto, proto)
		pr.Out.Header.Set(woos.HeaderXForwardedServer, woos.Name)
		if port, ok := pr.Out.Context().Value(woos.CtxPort).(string); ok {
			pr.Out.Header.Set("X-Forwarded-Port", port)
		}
		pr.Out.Header.Add(woos.HeaderVia, fmt.Sprintf("1.1 %s", woos.Name))
	}

	b.Proxy = rp
	b.rnd = rand.New(rand.NewSource(time.Now().UnixNano()))
	if b.hcConfig != nil && b.hcConfig.Path != "" {
		go b.healthCheckLoop(cbThreshold)
	}
	return b, nil
}

func (b *Backend) Jitter(interval time.Duration) time.Duration {
	return time.Duration(b.rnd.Int63n(int64(interval / woos.HealthCheckJitterFraction)))
}

func (b *Backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// If backend is Dead, reject immediately
	if BackendState(b.state.Load()) == StateDead {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	// If Draining, we allow existing requests (handled by Balancer pick logic usually),
	// but if it got here, we serve it to drain the queue.

	if !b.alive.Load() {
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

// Drain marks the backend as draining and waits for in-flight requests to complete.
func (b *Backend) Drain(timeout time.Duration) {
	if !b.state.CompareAndSwap(int32(StateActive), int32(StateDraining)) {
		return // Already draining or dead
	}

	b.logger.Fields("backend", b.URL.Host).Info("backend draining started")

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	deadline := time.Now().Add(timeout)

	for {
		if time.Now().After(deadline) {
			b.logger.Fields("backend", b.URL.Host, "in_flight", b.Activity.InFlight.Load()).Warn("backend drain timeout, force closing")
			break
		}

		if b.Activity.InFlight.Load() == 0 {
			break
		}

		select {
		case <-ticker.C:
			continue
		}
	}

	b.state.Store(int32(StateDead))
}

func (b *Backend) Stop() {
	b.stopOnce.Do(func() {
		close(b.stop)
		b.state.Store(int32(StateDead))

		// Close idle connections in transport
		if tp, ok := b.Proxy.Transport.(*http.Transport); ok {
			tp.CloseIdleConnections()
		}
	})
}

func (b *Backend) Uptime() time.Duration {
	return time.Since(b.startTime)
}

func (b *Backend) LastRecovery() time.Time {
	return time.Unix(0, b.lastRecovery.Load())
}

func (b *Backend) healthCheckLoop(cbThreshold int) {
	defer func() {
		if r := recover(); r != nil {
			b.logger.Fields("panic", r, "stack", string(debug.Stack()), "backend", b.URL.Host).
				Error("health check loop panicked (recovered)")
		}
	}()

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

	expectedStatus := b.hcConfig.ExpectedStatus
	expectedBody := b.hcConfig.ExpectedBody
	method := b.hcConfig.Method
	if method == "" {
		method = "GET"
	}

	hostHeader := ""
	if v, ok := b.hcConfig.Headers["Host"]; ok {
		hostHeader = v
	} else if len(b.routeDomains) > 0 {
		hostHeader = b.routeDomains[0]
	}

	for {
		select {
		case <-b.stop:
			return
		case <-timer.C:
			// If draining or dead, skip health checks
			if BackendState(b.state.Load()) != StateActive {
				return
			}

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			req, err := http.NewRequestWithContext(ctx, method, targetURL, nil)

			if err == nil {
				if hostHeader != "" {
					req.Host = hostHeader
				}
				for k, v := range b.hcConfig.Headers {
					if k != "Host" {
						req.Header.Set(k, v)
					}
				}
			}

			var resp *http.Response
			if err == nil {
				resp, err = client.Do(req)
			}
			cancel()

			healthy := false
			if err == nil && resp != nil {
				if len(expectedStatus) > 0 {
					if slices.Contains(expectedStatus, resp.StatusCode) {
						healthy = true
					}
				} else {
					healthy = resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusBadRequest
				}

				if healthy && expectedBody != "" {
					bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*10))
					if !strings.Contains(string(bodyBytes), expectedBody) {
						healthy = false
					}
				}

				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}

			if healthy {
				failures = 0
				b.Health.RecordSuccess()
				b.Activity.Failures.Store(0)
				if !b.alive.Load() {
					b.alive.Store(true)
					b.lastRecovery.Store(time.Now().UnixNano())
					b.logger.Fields("backend", b.URL.Host).Info("backend recovered")
				}
			} else {
				failures++
				b.Health.RecordFailure()
				newFailures := b.Activity.Failures.Add(1)

				if cbThreshold > 0 && (failures >= int64(threshold) || newFailures >= uint64(cbThreshold)) {
					if b.alive.Swap(false) {
						b.logger.Fields("backend", b.URL.Host, "failures", failures).Warn("circuit breaker tripped")
					}
				}
			}
			timer.Reset(interval + b.Jitter(interval))
		}
	}
}
func (b *Backend) Status(v bool)   { b.alive.Store(v) }
func (b *Backend) Alive() bool     { return b.alive.Load() && BackendState(b.state.Load()) == StateActive }
func (b *Backend) Weight() int     { return b.weight }
func (b *Backend) InFlight() int64 { return b.Activity.InFlight.Load() }
func (b *Backend) ResponseTime() int64 {
	snap := b.Activity.Latency.Snapshot()
	if snap.Count == 0 {
		return 0
	}
	return snap.Avg
}

var _ lb.Backend = (*Backend)(nil)
