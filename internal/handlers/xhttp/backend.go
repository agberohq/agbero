package xhttp

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/handlers/upstream"
	"github.com/agberohq/agbero/internal/hub/resource"
	"github.com/agberohq/agbero/internal/pkg/health"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
)

var proxyBufPool = zulu.NewBufferPool()

type backendCtxKey struct{}

// backendState holds per-request failure state. Pooled to eliminate the
// new(bool) heap allocation per proxied request. Stored in context under
// the comparable backendCtxKey so the fixed ErrorHandler closure can
// signal failure back to ServeHTTP's defer.
type backendState struct {
	failed bool
}

var backendStatePool = sync.Pool{New: func() any { return &backendState{} }}

type basicStatusWriter struct {
	http.ResponseWriter
	code int
}

func (b *basicStatusWriter) WriteHeader(code int) {
	b.code = code
	b.ResponseWriter.WriteHeader(code)
}

func (b *basicStatusWriter) Flush() {
	if f, ok := b.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

type Backend struct {
	upstream.Base

	Proxy *httputil.ReverseProxy
	Abort *health.EarlyAbortController

	stop     chan struct{}
	stopOnce sync.Once
	Cond     *Conditions
	logger   *ll.Logger

	hcConfig     *alaye.HealthCheck
	routeDomains []string
	Fallback     http.Handler
}

// NewBackend constructs an HTTP reverse proxy backend from the given config.
// Logger is sourced from Resource.Logger — no separate logger parameter is needed.
func NewBackend(xhttpCfg ConfigBackend) (*Backend, error) {
	u, err := xhttpCfg.Server.Address.URL()
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" {
		return nil, errors.Newf("%w :(http or https)", def.ErrBackendMissingScheme)
	}
	if u.Host == "" {
		return nil, def.ErrBackendMissingHost
	}
	switch u.Scheme {
	case def.Http, def.Https:
	default:
		return nil, errors.Newf("%w: %q", def.ErrBackendBadScheme, u.Scheme)
	}

	cond, err := NewConditions(xhttpCfg.Server.Criteria)
	if err != nil {
		return nil, err
	}

	route := xhttpCfg.Route
	if route == nil {
		route = &alaye.Route{Path: "/"}
	}

	logger := xhttpCfg.Resource.Logger
	if logger == nil {
		logger = ll.New("backend").Disable()
	}

	domain := "*"
	if len(xhttpCfg.Domains) > 0 && xhttpCfg.Domains[0] != "" {
		domain = xhttpCfg.Domains[0]
	}

	statsKey := route.KeyBackend(domain, xhttpCfg.Server.Address.String())

	cbThreshold := int64(def.DefaultCircuitBreakerThreshold)
	if route.CircuitBreaker.Threshold > 0 {
		cbThreshold = int64(route.CircuitBreaker.Threshold)
	}

	hasProber := route.HealthCheck.Enabled.Active() || (route.HealthCheck.Enabled == expect.Unknown && route.HealthCheck.Path != "")

	baseCfg := upstream.Config{
		Address:        xhttpCfg.Server.Address.String(),
		Weight:         xhttpCfg.Server.Weight,
		MaxConnections: xhttpCfg.Server.MaxConnections,
		CBThreshold:    cbThreshold,
		HasProber:      hasProber,
		StatsKey:       statsKey,
		Resource:       xhttpCfg.Resource,
	}

	base, err := upstream.NewBase(baseCfg)
	if err != nil {
		return nil, err
	}

	b := &Backend{
		Base:     base,
		Cond:     cond,
		hcConfig: &route.HealthCheck,
		logger:   logger,
		stop:     make(chan struct{}),
		Fallback: xhttpCfg.Fallback,
	}

	if len(xhttpCfg.Domains) > 0 {
		b.routeDomains = make([]string, len(xhttpCfg.Domains))
		copy(b.routeDomains, xhttpCfg.Domains)
	}

	b.Abort = health.NewEarlyAbortController(b.Weights.EarlyAbortEnabled)

	rp := &httputil.ReverseProxy{
		BufferPool: proxyBufPool,
	}
	t := xhttpCfg.Resource.Transport.Clone()
	t.Proxy = nil
	t.ExpectContinueTimeout = 0
	if xhttpCfg.Server.Streaming.Enabled.Active() {
		t.ResponseHeaderTimeout = 0
		rp.FlushInterval = xhttpCfg.Server.Streaming.EffectiveFlushInterval()
		if rp.FlushInterval <= 0 {
			rp.FlushInterval = -1
		}
	} else {
		rp.FlushInterval = 0
	}
	rp.Transport = t

	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		if errors.Is(err, context.Canceled) {
			b.logger.Fields("backend", u.Host, "remote", r.RemoteAddr).Debug("client disconnected early")
			w.WriteHeader(499)
			return
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			http.Error(w, "Gateway Timeout", http.StatusGatewayTimeout)
			return
		}
		if errors.Is(err, context.DeadlineExceeded) {
			http.Error(w, "Gateway Timeout", http.StatusGatewayTimeout)
			return
		}
		if err != nil && strings.Contains(err.Error(), "request body too large") {
			http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
			return
		}
		if state, ok := r.Context().Value(backendCtxKey{}).(*backendState); ok {
			state.failed = true
		}
		b.logger.Fields("backend", u.Host, "err", err).Error("proxy dial error")
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
		isWebSocket := pr.In.Header.Get("Upgrade") == "websocket"
		if isWebSocket {
			pr.Out.Header.Set("Upgrade", "websocket")
			pr.Out.Header.Set("Connection", "Upgrade")
			for _, h := range hopHeaders {
				if h != def.HeaderKeyUpgrade && h != def.HeaderKeyConnection {
					pr.Out.Header.Del(h)
				}
			}
		} else {
			for _, h := range hopHeaders {
				pr.Out.Header.Del(h)
			}
		}
		proto := def.Http
		if pr.In.TLS != nil {
			proto = def.Https
		}
		pr.Out.Header.Set(def.HeaderXForwardedHost, pr.In.Host)
		pr.Out.Header.Set(def.HeaderXForwardedProto, proto)
		pr.Out.Header.Set(def.HeaderXForwardedServer, def.Name)
		if lctx, ok := pr.Out.Context().Value(woos.ListenerCtxKey).(woos.ListenerCtx); ok && lctx.Port != "" {
			pr.Out.Header.Set("X-Forwarded-Port", lctx.Port)
		}
	}

	b.Proxy = rp

	if err := b.initHealth(xhttpCfg.Resource, u.ResolveReference(&url.URL{Path: b.hcConfig.Path}).String()); err != nil {
		b.logger.Fields("backend", b.Address, "err", err).Warn("failed to initialize health check")
	}

	return b, nil
}

func (b *Backend) initHealth(res *resource.Resource, targetURL string) error {
	if !b.HasProber {
		return nil
	}
	if res.Doctor == nil {
		return errors.New("doctor is nil")
	}
	probeCfg := health.DefaultProbeConfig()
	if b.hcConfig.Path != "" {
		probeCfg.Path = b.hcConfig.Path
	}
	if b.hcConfig.Interval > 0 {
		probeCfg.StandardInterval = b.hcConfig.Interval.StdDuration()
	}
	if b.hcConfig.Timeout > 0 {
		probeCfg.Timeout = b.hcConfig.Timeout.StdDuration()
	}
	headers := http.Header{}
	hostHeader := ""
	for k, v := range b.hcConfig.Headers {
		if k == "Host" {
			hostHeader = v
		} else {
			headers.Set(k, v)
		}
	}
	if hostHeader == "" && len(b.routeDomains) > 0 && b.routeDomains[0] != "*" {
		hostHeader = b.routeDomains[0]
	}

	probeClient := &http.Client{
		Timeout:   probeCfg.Timeout,
		Transport: b.Proxy.Transport,
	}
	executor := &HTTPExecutor{
		URL:            targetURL,
		Method:         b.hcConfig.Method,
		Client:         probeClient,
		Header:         headers,
		Host:           hostHeader,
		ExpectedStatus: b.hcConfig.ExpectedStatus,
		ExpectedBody:   b.hcConfig.ExpectedBody,
	}
	return b.RegisterHealth(probeCfg, func(ctx context.Context) error {
		success, latency, err := executor.Probe(ctx)
		b.HealthScore.Update(health.Record{
			ProbeLatency: latency,
			ProbeSuccess: success,
			ConnHealth:   100,
			PassiveRate:  b.HealthScore.PassiveErrorRate(),
		})
		if !success {
			if err != nil {
				return err
			}
			return errors.New("http probe failed")
		}
		return nil
	}, nil)
}

// ServeHTTP proxies the request to the upstream backend.
// Applies circuit breaker and early abort checks before forwarding.
func (b *Backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !b.AcquireCircuit() {
		if b.Fallback != nil {
			b.Fallback.ServeHTTP(w, r)
		} else {
			http.Error(w, "Service Unavailable (Circuit Breaker)", http.StatusServiceUnavailable)
		}
		return
	}
	if b.Abort.ShouldAbort(b.HealthScore) {
		if b.Fallback != nil {
			b.Fallback.ServeHTTP(w, r)
		} else {
			http.Error(w, "Service Unavailable (Health)", http.StatusServiceUnavailable)
		}
		return
	}

	start := time.Now()
	b.Activity.StartRequest()

	state := backendStatePool.Get().(*backendState)
	state.failed = false
	ctx := context.WithValue(r.Context(), backendCtxKey{}, state)
	req := r.WithContext(ctx)

	var actualWriter http.ResponseWriter = w
	var sw *basicStatusWriter

	if _, ok := w.(*zulu.ResponseWriter); !ok {
		sw = &basicStatusWriter{ResponseWriter: w, code: 200}
		actualWriter = sw
	}

	defer func() {
		dur := time.Since(start)
		failed := state.failed
		backendStatePool.Put(state)
		if rw, ok := w.(*zulu.ResponseWriter); ok {
			if rw.StatusCode == http.StatusBadGateway ||
				rw.StatusCode == http.StatusServiceUnavailable ||
				rw.StatusCode == http.StatusGatewayTimeout {
				failed = true
			}
		} else if sw != nil {
			if sw.code == http.StatusBadGateway ||
				sw.code == http.StatusServiceUnavailable ||
				sw.code == http.StatusGatewayTimeout {
				failed = true
			}
		}
		b.Activity.EndRequest(dur.Microseconds(), failed)
		if b.HealthScore != nil {
			b.HealthScore.RecordPassiveRequest(!failed)
		}
		if justTripped := b.RecordResult(!failed); justTripped {
			b.logger.Fields("backend", b.Address, "failures", b.CBThreshold).Warn("circuit breaker tripped")
		}
	}()

	b.Proxy.ServeHTTP(actualWriter, req)
}

// Drain waits for in-flight requests to complete up to the given timeout.
func (b *Backend) Drain(timeout time.Duration) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.Now().Add(timeout)
	for {
		if b.Activity.InFlight.Load() <= 0 {
			break
		}
		if time.Now().After(deadline) {
			b.logger.Fields("backend", b.Address, "in_flight", b.Activity.InFlight.Load()).Warn("backend drain timeout, force closing")
			break
		}
		<-ticker.C
	}
}

// Stop closes the backend and drains the transport idle connections.
func (b *Backend) Stop() {
	b.stopOnce.Do(func() {
		close(b.stop)
		if b.HasProber {
			if doc, ok := b.Doctor().(*jack.Doctor); ok && doc != nil {
				doc.Stop(b.PatientID)
			}
		}
		if tp, ok := b.Proxy.Transport.(*http.Transport); ok {
			tp.CloseIdleConnections()
		}
	})
}

// RouteDomains returns the domains this backend serves.
func (b *Backend) RouteDomains() []string {
	return b.routeDomains
}
