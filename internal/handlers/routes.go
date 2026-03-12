package handlers

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/handlers/xhttp"
	"github.com/agberohq/agbero/internal/middleware/attic"
	"github.com/agberohq/agbero/internal/middleware/auth"
	"github.com/agberohq/agbero/internal/middleware/compress"
	"github.com/agberohq/agbero/internal/middleware/cors"
	"github.com/agberohq/agbero/internal/middleware/errorpages"
	"github.com/agberohq/agbero/internal/middleware/headers"
	"github.com/agberohq/agbero/internal/middleware/ipallow"
	"github.com/agberohq/agbero/internal/middleware/ratelimit"
	"github.com/agberohq/agbero/internal/middleware/rewrite"
	"github.com/agberohq/agbero/internal/operation"
	"github.com/agberohq/agbero/internal/pkg/cook"
	"github.com/agberohq/agbero/internal/pkg/health"
	"github.com/agberohq/agbero/internal/pkg/metrics"
	"github.com/agberohq/agbero/internal/pkg/wellknown"
	"github.com/olekukonko/ll"
)

type Config struct {
	Global  *alaye.Global
	Host    *alaye.Host
	Logger  *ll.Logger
	IPMgr   *zulu.IPManager
	CookMgr *cook.Manager
}

type Route struct {
	handler  http.Handler
	Backends []*xhttp.Backend
	ipMgr    *zulu.IPManager
	global   *alaye.Global
}

func NewRoute(cfg Config, route *alaye.Route) *Route {
	if route == nil {
		return FallbackRoute("nil route")
	}

	woos.DefaultRoute(route)

	cfg.Logger.Fields("path", route.Path, "enabled", route.Enabled).Debug("creating route")
	if err := route.Validate(); err != nil {
		cfg.Logger.Fields("path", route.Path, "err", err).Error("invalid route config")
		return FallbackRoute("invalid route config: " + err.Error())
	}

	isWebRoute := route.Web.Root.IsSet() || route.Web.Git.Enabled.Active()
	hasBackends := len(route.Backends.Servers) > 0

	if isWebRoute && hasBackends {
		return FallbackRoute("route cannot have both web and proxy config")
	}

	if isWebRoute {
		return newWebRoute(cfg, route)
	}
	if hasBackends {
		return newProxyRoute(cfg, route)
	}

	return FallbackRoute("route has no handler configuration")
}

func (h *Route) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.handler == nil {
		http.Error(w, "route handler not initialized", http.StatusBadGateway)
		return
	}
	h.handler.ServeHTTP(w, r)
}

func (h *Route) Close() {
	if len(h.Backends) > 0 {
		var wg sync.WaitGroup

		drainTimeout := woos.DefaultTransportDrainTimeout
		if h.global != nil && h.global.Timeouts.Read > 0 {
			drainTimeout = h.global.Timeouts.Read + woos.DefaultTransportResponseHeaderTimeout
			if drainTimeout < woos.DefaultTransportDrainTimeout {
				drainTimeout = woos.DefaultTransportDrainTimeout
			}
		}

		for _, b := range h.Backends {
			if b != nil {
				wg.Add(1)
				go func(be *xhttp.Backend, timeout time.Duration) {
					defer wg.Done()
					be.Drain(timeout)
					be.Stop()
				}(b, drainTimeout)
			}
		}
		wg.Wait()
	}
}

func newWebRoute(cfg Config, route *alaye.Route) *Route {
	chain := http.Handler(operation.NewWeb(cfg.Logger, route, cfg.CookMgr))

	ipMgr := zulu.NewIPManager(cfg.Global.Security.TrustedProxies)

	if len(route.AllowedIPs) > 0 {
		chain = ipallow.New(route.AllowedIPs, cfg.Logger, ipMgr)(chain)
	}

	chain = auth.JWT(&route.JWTAuth)(chain)
	chain = auth.Basic(&route.BasicAuth)(chain)
	chain = auth.Forward(&route.ForwardAuth)(chain)
	chain = auth.OAuth(&route.OAuth)(chain)

	if rl := buildRouteLimiter(&route.RateLimit, &cfg.Global.RateLimits, ipMgr); rl != nil {
		chain = rl.Handler(chain)
	}

	chain = headers.Headers(&route.Headers)(chain)
	chain = compress.Compress(route)(chain)

	chain = attic.New(&route.Cache, cfg.Logger)(chain)

	errCfg := errorpages.Config{
		RoutePages:  route.ErrorPages,
		HostPages:   cfg.Host.ErrorPages,
		GlobalPages: cfg.Global.ErrorPages,
	}
	chain = errorpages.New(errCfg)(chain)

	chain = cors.New(&route.CORS)(chain)
	chain = rewrite.New(cfg.Logger, route.StripPrefixes, route.Rewrites)(chain)

	return &Route{
		handler:  chain,
		Backends: nil,
		ipMgr:    ipMgr,
		global:   cfg.Global,
	}
}

func newProxyRoute(cfg Config, route *alaye.Route) *Route {
	var backends []*xhttp.Backend
	for i, backendCfg := range route.Backends.Servers {
		domain := "*"
		if len(cfg.Host.Domains) > 0 && cfg.Host.Domains[0] != "" {
			domain = cfg.Host.Domains[0]
		}

		statsKey := route.BackendKey(domain, backendCfg.Address)
		hScore, _ := health.GlobalRegistry.Get(statsKey)

		b, err := xhttp.NewBackend(backendCfg, xhttp.ConfigBackend{
			Route:       route,
			Domains:     cfg.Host.Domains,
			Logger:      cfg.Logger,
			Registry:    metrics.DefaultRegistry,
			Fallback:    nil,
			HealthScore: hScore,
		})
		if err != nil {
			cfg.Logger.Fields("index", i, "backend", backendCfg.Address, "err", err).Error("failed to create backend")
			continue
		}
		backends = append(backends, b)
	}

	fallbackCfg := resolveFallback(&route.Fallback, &cfg.Global.Fallback)
	var fallbackHandler http.Handler
	if fallbackCfg.IsActive() {
		fallbackHandler = buildFallbackHandler(fallbackCfg, cfg.Logger)
	}

	if len(backends) == 0 {
		if fallbackHandler != nil {
			return &Route{
				handler:  fallbackHandler,
				Backends: nil,
				ipMgr:    cfg.IPMgr,
				global:   cfg.Global,
			}
		}
		return FallbackRoute("proxy route missing backends")
	}

	if fallbackHandler != nil {
		for _, b := range backends {
			b.Fallback = fallbackHandler
		}
	}

	timeout := cfg.Global.Timeouts.Read
	if route.Timeouts.Request != 0 {
		timeout = route.Timeouts.Request
	}

	balancerCfg := xhttp.ConfigProxy{
		Strategy: route.Backends.Strategy,
		Keys:     route.Backends.Keys,
		Timeout:  timeout,
		Fallback: fallbackHandler,
	}

	loadBalancer := xhttp.NewProxy(balancerCfg, backends, cfg.IPMgr)

	var chain http.Handler = loadBalancer

	if len(route.AllowedIPs) > 0 {
		chain = ipallow.New(route.AllowedIPs, cfg.Logger, cfg.IPMgr)(chain)
	}

	chain = auth.JWT(&route.JWTAuth)(chain)
	chain = auth.Basic(&route.BasicAuth)(chain)
	chain = auth.Forward(&route.ForwardAuth)(chain)
	chain = auth.OAuth(&route.OAuth)(chain)

	if rl := buildRouteLimiter(&route.RateLimit, &cfg.Global.RateLimits, cfg.IPMgr); rl != nil {
		chain = rl.Handler(chain)
	}

	chain = headers.Headers(&route.Headers)(chain)
	chain = compress.Compress(route)(chain)

	chain = attic.New(&route.Cache, cfg.Logger)(chain)

	errCfg := errorpages.Config{
		RoutePages:  route.ErrorPages,
		HostPages:   cfg.Host.ErrorPages,
		GlobalPages: cfg.Global.ErrorPages,
	}
	chain = errorpages.New(errCfg)(chain)

	chain = cors.New(&route.CORS)(chain)
	chain = rewrite.New(cfg.Logger, route.StripPrefixes, route.Rewrites)(chain)

	return &Route{
		handler:  chain,
		Backends: backends,
		ipMgr:    cfg.IPMgr,
		global:   cfg.Global,
	}
}

func resolveFallback(routeFallback, globalFallback *alaye.Fallback) *alaye.Fallback {
	if routeFallback.Enabled.Active() {
		return routeFallback
	}
	if routeFallback.Enabled == alaye.Unknown && globalFallback.IsActive() {
		return globalFallback
	}
	return routeFallback
}

func buildFallbackHandler(fallback *alaye.Fallback, logger *ll.Logger) http.Handler {
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
				w.Header().Set("Cache-Control", "public, max-age="+string(rune(cacheTTL)))
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
			logger.Fields("err", err, "proxy_url", fallback.ProxyURL).Error("invalid fallback proxy URL")
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "Fallback configuration error", http.StatusInternalServerError)
			})
		}
		proxy := httputil.NewSingleHostReverseProxy(proxyURL)
		proxy.Rewrite = func(pr *httputil.ProxyRequest) {
			pr.SetXForwarded()
			pr.Out.Host = proxyURL.Host
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

func buildRouteLimiter(rlc *alaye.RouteRate, global *alaye.GlobalRate, ipMgr *zulu.IPManager) *ratelimit.RateLimiter {
	if rlc == nil {
		return nil
	}
	if !rlc.Enabled.Active() && rlc.UsePolicy == "" {
		return nil
	}
	ttl := woos.DefaultRateTTL
	maxEntries := woos.DefaultRateMaxEntries

	if global != nil {
		if global.TTL > 0 {
			ttl = global.TTL
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
		path := r.URL.Path
		if wellknown.IsACMEChallengePrefix(path) {
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
				for _, p := range rule.Prefixes {
					if strings.HasPrefix(path, p) {
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
				Window:   rule.Window,
				Burst:    rule.Burst,
				KeySpec:  rule.Key,
			}, true
		}
		return "", ratelimit.RatePolicy{}, false
	}
	return ratelimit.New(ratelimit.Config{
		TTL:        ttl,
		MaxEntries: maxEntries,
		Policy:     policy,
		IPManager:  ipMgr,
	})
}
