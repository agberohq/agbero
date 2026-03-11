package xhttp

import (
	"context"
	"fmt"
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
	"git.imaxinacion.net/aibox/agbero/internal/pkg/health"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/lb"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/metrics"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/ll"
)

type ctxKeyFailed struct{}

type Backend struct {
	URL   *url.URL
	Proxy *httputil.ReverseProxy

	HealthScore *health.Score
	Weights     health.Multiplier
	Abort       *health.EarlyAbortController

	stop         chan struct{}
	stopOnce     sync.Once
	startTime    time.Time
	lastRecovery atomic.Int64
	weight       int
	cbThreshold  int
	hasProber    bool
	Cond         *Conditions
	rnd          *rand.Rand
	logger       *ll.Logger

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

	cbThreshold := woos.DefaultCircuitBreakerThreshold
	if route.CircuitBreaker.Threshold > 0 {
		cbThreshold = route.CircuitBreaker.Threshold
	}

	var hScore *health.Score
	if xhttpCfg.HealthScore != nil {
		hScore = xhttpCfg.HealthScore
	} else {
		// Use the global registry directly if it wasn't passed down
		hScore = health.GlobalRegistry.GetOrSet(statsKey, health.NewScore(health.DefaultThresholds(), health.DefaultScoringWeights(), health.DefaultLatencyThresholds(), nil))
	}

	b := &Backend{
		URL:          u,
		weight:       cfg.Weight,
		cbThreshold:  cbThreshold,
		Cond:         cond,
		hcConfig:     &route.HealthCheck,
		logger:       logger,
		stop:         make(chan struct{}),
		startTime:    now,
		lastRecovery: atomic.Int64{},
		Activity:     stats.Activity,
		Fallback:     xhttpCfg.Fallback,
		HealthScore:  hScore,
	}

	b.lastRecovery.Store(now.UnixNano())

	if len(xhttpCfg.Domains) > 0 {
		b.routeDomains = make([]string, len(xhttpCfg.Domains))
		copy(b.routeDomains, xhttpCfg.Domains)
	}

	b.Weights = health.DefaultRoutingMultiplier()
	b.Abort = health.NewEarlyAbortController(b.Weights.EarlyAbortEnabled)

	if b.hcConfig != nil {
		if b.hcConfig.Enabled.Active() {
			b.hasProber = true
		} else if b.hcConfig.Enabled == alaye.Unknown && b.hcConfig.Path != "" {
			b.hasProber = true
		} else {
			b.hasProber = false
		}
	}

	rp := &httputil.ReverseProxy{}
	t := woos.Transport.Clone()
	t.Proxy = nil
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

		// Signal the ServeHTTP defer block that this request failed
		if ptr, ok := r.Context().Value(ctxKeyFailed{}).(*bool); ok {
			*ptr = true
		}

		b.HealthScore.RecordPassiveRequest(false)
		b.HealthScore.Update(health.Record{
			ProbeSuccess: false,
			ConnHealth:   0,
			PassiveRate:  b.HealthScore.PassiveErrorRate(),
		})

		newFailures := b.Activity.Failures.Add(1)

		if b.cbThreshold > 0 && newFailures >= uint64(b.cbThreshold) {
			b.logger.Fields("backend", u.Host, "failures", newFailures).Warn("circuit breaker tripped")
		}

		if !b.hasProber && !b.Alive() && time.Since(b.LastRecovery()) > 5*time.Second {
			b.Activity.Failures.Store(0)
			b.lastRecovery.Store(time.Now().UnixNano())
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
		http.Error(w, "Bad Proxy", http.StatusBadGateway)
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

	return b, nil
}

func (b *Backend) HasProber() bool {
	return b.hasProber
}

func (b *Backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if b.Abort.ShouldAbort(b.URL.String(), b.HealthScore) {
		if b.Fallback != nil {
			b.Fallback.ServeHTTP(w, r)
		} else {
			http.Error(w, "Service Unavailable (Health)", http.StatusServiceUnavailable)
		}
		return
	}

	start := time.Now()
	b.Activity.StartRequest()

	failedPtr := new(bool)
	ctx := context.WithValue(r.Context(), ctxKeyFailed{}, failedPtr)
	req := r.WithContext(ctx)

	defer func() {
		dur := time.Since(start).Microseconds()
		failed := *failedPtr

		b.Activity.EndRequest(dur, failed)
		b.HealthScore.RecordPassiveRequest(!failed)

		b.HealthScore.Update(health.Record{
			ProbeSuccess: !failed,
			ConnHealth:   100,
			PassiveRate:  b.HealthScore.PassiveErrorRate(),
		})
	}()

	b.Proxy.ServeHTTP(w, req)
}

func (b *Backend) Drain(timeout time.Duration) {
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
}

func (b *Backend) Stop() {
	b.stopOnce.Do(func() {
		close(b.stop)
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

func (b *Backend) Status(v bool) {
	if !v {
		b.HealthScore.Update(health.Record{
			ProbeSuccess: false,
			ConnHealth:   0,
			PassiveRate:  1.0,
		})
		b.Activity.Failures.Store(uint64(b.cbThreshold + 1))
	} else {
		b.HealthScore.Update(health.Record{
			ProbeLatency: 10 * time.Millisecond,
			ProbeSuccess: true,
			ConnHealth:   100,
			PassiveRate:  0,
		})
		b.Activity.Failures.Store(0)
	}
}

func (b *Backend) Alive() bool {
	if b.cbThreshold > 0 && b.Activity.Failures.Load() >= uint64(b.cbThreshold) {
		return false
	}
	if !b.hasProber || b.HealthScore == nil {
		return true
	}
	state := b.HealthScore.State()
	return state != health.StateDead && state != health.StateUnhealthy
}

func (b *Backend) Weight() int {
	if b.HealthScore == nil {
		return b.weight
	}
	return b.Weights.EffectiveWeight(b.weight, b.HealthScore)
}

func (b *Backend) InFlight() int64 { return b.Activity.InFlight.Load() }

func (b *Backend) ResponseTime() int64 {
	snap := b.Activity.Latency.Snapshot()
	if snap.Count == 0 {
		return 0
	}
	return snap.Avg
}

var _ lb.Backend = (*Backend)(nil)
