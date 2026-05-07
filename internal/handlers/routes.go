package handlers

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/handlers/web"
	"github.com/agberohq/agbero/internal/handlers/xhttp"
	"github.com/agberohq/agbero/internal/handlers/xserverless"
	resource "github.com/agberohq/agbero/internal/hub/resource"
	"github.com/agberohq/agbero/internal/middleware/attic"
	"github.com/agberohq/agbero/internal/middleware/auth"
	"github.com/agberohq/agbero/internal/middleware/compress"
	"github.com/agberohq/agbero/internal/middleware/cors"
	"github.com/agberohq/agbero/internal/middleware/errorpages"
	"github.com/agberohq/agbero/internal/middleware/headers"
	"github.com/agberohq/agbero/internal/middleware/ipallow"
	"github.com/agberohq/agbero/internal/middleware/nonce"
	"github.com/agberohq/agbero/internal/middleware/ratelimit"
	"github.com/agberohq/agbero/internal/middleware/rewrite"
	"github.com/agberohq/agbero/internal/middleware/waf"
	"github.com/agberohq/agbero/internal/pkg/tunnel"
	"github.com/agberohq/agbero/internal/pkg/wellknown"
	"github.com/olekukonko/ll"
)

type Route struct {
	handler   http.Handler
	Backends  []*xhttp.Backend
	Proxy     *xhttp.Proxy
	ipMgr     *zulu.IPManager
	global    *alaye.Global
	resource  *resource.Resource
	lastTouch atomic.Int64
}

func NewRoute(cfg resource.Proxy, route *alaye.Route) *Route {
	if route == nil {
		return FallbackRoute("nil route")
	}
	if err := cfg.Validate(); err != nil {
		return FallbackRoute("invalid config: " + err.Error())
	}
	woos.DefaultRoute(route)
	cfg.Resource.Logger.Fields("path", route.Path, "enabled", route.Enabled).Debug("creating route")
	if err := route.Validate(); err != nil {
		cfg.Resource.Logger.Fields("path", route.Path, "err", err).Error("invalid route config")
		return FallbackRoute("invalid route config: " + err.Error())
	}

	nonceStores := buildNonceStores(route)

	var primary http.Handler
	if route.Serverless.Enabled.Active() {
		primary = xserverless.NewWithNonces(cfg, route, nonceStores)
	} else if route.Web.Root.IsSet() || route.Web.Git.Enabled.Active() {
		primary = web.NewWebWithNonces(cfg.Resource, route, cfg.CookMgr, nonceStores)
	} else {
		return newProxyRoute(cfg, route)
	}

	return wrapHandler(cfg, route, primary)
}

func wrapHandler(cfg resource.Proxy, route *alaye.Route, primary http.Handler) *Route {
	chain := primary
	ipMgr := zulu.NewIPManager(cfg.Global.Security.Allow.Proxies)

	if len(route.AllowedIPs) > 0 {
		chain = ipallow.New(route.AllowedIPs, cfg.Resource.Logger, ipMgr)(chain)
	}
	chain = auth.JWT(&route.JWTAuth)(chain)
	chain = auth.Basic(&route.BasicAuth, cfg.Resource.Logger)(chain)
	chain = auth.Forward(cfg.Resource, &route.ForwardAuth)(chain)
	chain = auth.OAuth(&route.OAuth)(chain)

	if rl := buildRouteLimiter(&route.RateLimit, &cfg.Global.RateLimits, ipMgr, cfg.SharedState); rl != nil {
		chain = rl.Handler(chain)
	}

	// WAF: after rate limiting, before cache. Blocked requests never hit the backend or cache.
	wafEngine, err := waf.NewForRoute(waf.RouteConfig{
		Global: &cfg.Global.Security.WAF,
		Route:  &route.WAF,
		Logger: cfg.Resource.Logger,
	})
	if err != nil {
		cfg.Resource.Logger.Fields("path", route.Path, "err", err).Error("waf: failed to build engine, skipping")
	}
	chain = wafEngine.Middleware(chain) // nil-safe: no-op when wafEngine is nil

	chain = headers.Headers(&route.Headers)(chain)
	chain = compress.Compress(route)(chain)

	// Pass resource.Background pool so stale-while-revalidate revalidation
	// is submitted to an accountable pool that drains cleanly on shutdown.
	chain = attic.New(&route.Cache, cfg.Resource.Logger,
		attic.WithPool(cfg.Resource.Background),
	)(chain)

	errCfg := errorpages.Config{
		RoutePages:  route.ErrorPages,
		HostPages:   cfg.Host.ErrorPages,
		GlobalPages: cfg.Global.ErrorPages,
	}
	chain = errorpages.New(errCfg)(chain)
	chain = cors.New(&route.CORS)(chain)
	chain = rewrite.New(cfg.Resource.Logger, route.StripPrefixes, route.Rewrites)(chain)

	return &Route{
		handler:  chain,
		ipMgr:    ipMgr,
		global:   cfg.Global,
		resource: cfg.Resource,
	}
}

func newProxyRoute(cfg resource.Proxy, route *alaye.Route) *Route {
	var backends []*xhttp.Backend
	for i, backendCfg := range route.Backends.Servers {
		pool, err := resolveTunnelPool(route.Backends, cfg.TunnelPools, cfg.Resource.Logger)
		if err != nil {
			cfg.Resource.Logger.Fields("index", i, "backend", backendCfg.Address.String(), "err", err).Error("failed to resolve tunnel for backend")
			continue
		}
		b, err := xhttp.NewBackend(xhttp.ConfigBackend{
			Server:            backendCfg,
			Route:             route,
			Domains:           cfg.Host.Domains,
			Fallback:          nil,
			Resource:          cfg.Resource,
			TunnelPool:        pool,
			BulkheadPartition: route.Path,
			UseHedger:         route.Backends.Idempotent,
		})
		if err != nil {
			cfg.Resource.Logger.Fields("index", i, "backend", backendCfg.Address.String(), "err", err).Error("failed to create backend")
			continue
		}
		backends = append(backends, b)
	}

	fallbackCfg := resolveFallback(&route.Fallback, &cfg.Global.Fallback)
	var fallbackHandler http.Handler
	if fallbackCfg.IsActive() {
		safeDialer := &net.Dialer{}
		safeTransport := &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, fmt.Errorf("fallback proxy: invalid address %q: %w", addr, err)
				}
				ip := net.ParseIP(host)
				if ip == nil {
					return nil, fmt.Errorf("fallback proxy: could not parse resolved address %q", host)
				}
				if alaye.IsPrivateIP(ip) {
					return nil, fmt.Errorf("fallback proxy: SSRF protection blocked connection to private/internal address %s:%s", host, port)
				}
				return safeDialer.DialContext(ctx, network, addr)
			},
		}
		fallbackHandler = buildFallbackHandler(fallbackCfg, cfg.Resource.Logger, safeTransport)
	}

	if len(backends) == 0 {
		if fallbackHandler != nil {
			return &Route{
				handler:  fallbackHandler,
				Backends: nil,
				ipMgr:    cfg.IPMgr,
				global:   cfg.Global,
				resource: cfg.Resource,
			}
		}
		return FallbackRoute("proxy route missing backends")
	}

	if fallbackHandler != nil {
		for _, b := range backends {
			b.Fallback = fallbackHandler
		}
	}

	timeout := cfg.Global.Timeouts.Read.StdDuration()
	if route.Timeouts.Request != 0 {
		timeout = route.Timeouts.Request.StdDuration()
	}

	balancerCfg := xhttp.ConfigProxy{
		Strategy: route.Backends.Strategy,
		Keys:     route.Backends.Keys,
		Timeout:  timeout,
		Fallback: fallbackHandler,
	}
	loadBalancer := xhttp.NewProxy(balancerCfg, backends, cfg.IPMgr)
	return wrapHandler(cfg, route, loadBalancer)
}

func (h *Route) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.handler == nil {
		http.Error(w, "route handler not initialized", http.StatusBadGateway)
		return
	}
	h.handler.ServeHTTP(w, r)
}

func (h *Route) Close() error {
	if h.Proxy != nil {
		h.Proxy.Stop()
	}
	if len(h.Backends) > 0 {
		drainTimeout := def.DefaultTransportDrainTimeout
		if h.global != nil && h.global.Timeouts.Read > 0 {
			drainTimeout = max(
				h.global.Timeouts.Read.StdDuration()+def.DefaultTransportResponseHeaderTimeout,
				def.DefaultTransportDrainTimeout,
			)
		}
		for _, b := range h.Backends {
			if b != nil {
				be := b
				go func() {
					be.Drain(drainTimeout)
					be.Stop()
				}()
			}
		}
	}
	return nil
}

func resolveFallback(routeFallback, globalFallback *alaye.Fallback) *alaye.Fallback {
	if routeFallback.Enabled.Active() {
		return routeFallback
	}
	if routeFallback.Enabled == expect.Unknown && globalFallback.IsActive() {
		return globalFallback
	}
	return routeFallback
}

func buildFallbackHandler(fallback *alaye.Fallback, logger *ll.Logger, transport ...http.RoundTripper) http.Handler {
	var rt http.RoundTripper = http.DefaultTransport
	if len(transport) > 0 && transport[0] != nil {
		rt = transport[0]
	}
	switch strings.ToLower(fallback.Type) {
	case "static":
		body := []byte(fallback.Body)
		contentType := fallback.ContentType
		statusCode := fallback.StatusCode
		cacheTTL := fallback.CacheTTL
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if contentType != "" {
				w.Header().Set("Content-Type", contentType)
			}
			if cacheTTL > 0 {
				w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(cacheTTL))
			}
			w.WriteHeader(statusCode)
			if len(body) > 0 {
				_, _ = w.Write(body)
			}
		})
	case "redirect":
		redirectURL := fallback.RedirectURL
		statusCode := fallback.StatusCode
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, redirectURL, statusCode)
		})
	case "proxy":
		proxyURL, err := url.Parse(fallback.ProxyURL)
		if err != nil {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "Fallback configuration error", http.StatusInternalServerError)
			})
		}
		proxy := &httputil.ReverseProxy{
			Transport: rt,
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetXForwarded()
				pr.SetURL(proxyURL)
			},
		}
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Fields("err", err, "fallback_proxy", fallback.ProxyURL).Error("fallback proxy failed")
			http.Error(w, "Fallback service unavailable", http.StatusBadGateway)
		}
		return proxy
	default:
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		})
	}
}

func FallbackRoute(msg string) *Route {
	return &Route{
		handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, msg, http.StatusBadGateway)
		}),
	}
}

func buildRouteLimiter(rlc *alaye.RateRoute, global *alaye.RateGlobal, ipMgr *zulu.IPManager, sharedState woos.SharedState) *ratelimit.RateLimiter {
	if rlc == nil || (!rlc.Enabled.Active() && rlc.UsePolicy == "") {
		return nil
	}
	ttl := def.DefaultRateTTL
	maxEntries := def.DefaultRateMaxEntries
	if global != nil {
		if global.TTL > 0 {
			ttl = global.TTL.StdDuration()
		}
		if global.MaxEntries > 0 {
			maxEntries = global.MaxEntries
		}
	}
	var rules []alaye.RateRule
	if rlc.UsePolicy != "" && global != nil {
		for _, pol := range global.Policies {
			if pol.Name == rlc.UsePolicy {
				rules = append(rules, alaye.RateRule{
					Name:     pol.Name,
					Requests: pol.Requests,
					Window:   pol.Window,
					Burst:    pol.Burst,
					Key:      pol.Key,
				})
				break
			}
		}
	}
	if rlc.Rule.Enabled.Active() {
		rules = append(rules, rlc.Rule)
	}
	if len(rules) == 0 {
		return nil
	}
	policy := func(r *http.Request) (bucket string, pol ratelimit.RatePolicy, ok bool) {
		p := r.URL.Path
		if wellknown.IsACMEChallengePrefix(p) {
			return "", ratelimit.RatePolicy{}, false
		}
		for _, rule := range rules {
			if len(rule.Methods) > 0 {
				methodMatch := false
				for _, m := range rule.Methods {
					if strings.EqualFold(m, r.Method) {
						methodMatch = true
						break
					}
				}
				if !methodMatch {
					continue
				}
			}
			if len(rule.Prefixes) > 0 {
				prefixMatch := false
				for _, pref := range rule.Prefixes {
					if strings.HasPrefix(p, pref) {
						prefixMatch = true
						break
					}
				}
				if !prefixMatch {
					continue
				}
			}
			return rule.Name, ratelimit.RatePolicy{
				Requests: rule.Requests,
				Window:   rule.Window.StdDuration(),
				Burst:    rule.Burst,
				KeySpec:  rule.Key,
			}, true
		}
		return "", ratelimit.RatePolicy{}, false
	}
	return ratelimit.New(ratelimit.Config{
		TTL:         ttl,
		MaxEntries:  maxEntries,
		Policy:      policy,
		IPManager:   ipMgr,
		SharedState: sharedState,
	})
}

func buildNonceStores(route *alaye.Route) map[string]*nonce.Store {
	stores := make(map[string]*nonce.Store)
	for _, r := range route.Serverless.Replay {
		if r.Enabled.Active() && r.IsReplayMode() && r.Auth.Enabled.Active() && r.Auth.Method == "meta" {
			stores[r.Name] = nonce.NewStore(0)
		}
	}
	return stores
}

// resolveTunnelPool returns the tunnel.Pool for a backend block, or nil if
// no tunnel is configured (direct connection). It handles both the named
// `via` reference and the inline `tunnel = "socks5://..."` shorthand.
//
// Named references are resolved against the pools map built from global
// tunnel {} blocks. An unknown name is a fatal error logged by the caller.
func resolveTunnelPool(b alaye.Backend, pools map[string]*tunnel.Pool, logger *ll.Logger) (*tunnel.Pool, error) {
	// Named tunnel reference — looked up in the global registry.
	if b.Via != "" {
		pool, ok := pools[b.Via]
		if !ok {
			return nil, fmt.Errorf("backend references undefined tunnel %q — check global tunnel blocks", b.Via)
		}
		return pool, nil
	}
	// Inline socks5:// shorthand — build a one-off anonymous pool.
	if b.Tunnel != "" {
		pool, err := tunnel.NewFromURL(b.Tunnel)
		if err != nil {
			return nil, fmt.Errorf("backend tunnel %q: %w", b.Tunnel, err)
		}
		return pool, nil
	}
	// No tunnel configured — direct connection.
	return nil, nil
}
