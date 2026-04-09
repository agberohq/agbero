package handlers

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/handlers/web"
	"github.com/agberohq/agbero/internal/handlers/xhttp"
	"github.com/agberohq/agbero/internal/handlers/xserverless"
	resource2 "github.com/agberohq/agbero/internal/hub/resource"
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
	"github.com/agberohq/agbero/internal/pkg/wellknown"
	"github.com/olekukonko/ll"
)

type Route struct {
	handler   http.Handler
	Backends  []*xhttp.Backend
	Proxy     *xhttp.Proxy
	ipMgr     *zulu.IPManager
	global    *alaye.Global
	resource  *resource2.Resource
	lastTouch atomic.Int64
}

func NewRoute(cfg resource2.Proxy, route *alaye.Route) *Route {
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

func wrapHandler(cfg resource2.Proxy, route *alaye.Route, primary http.Handler) *Route {
	chain := primary
	ipMgr := zulu.NewIPManager(cfg.Global.Security.TrustedProxies)
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

	chain = headers.Headers(&route.Headers)(chain)
	chain = compress.Compress(route)(chain)
	chain = attic.New(&route.Cache, cfg.Resource.Logger)(chain)
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

func newProxyRoute(cfg resource2.Proxy, route *alaye.Route) *Route {
	var backends []*xhttp.Backend
	for i, backendCfg := range route.Backends.Servers {
		b, err := xhttp.NewBackend(xhttp.ConfigBackend{
			Server:   backendCfg,
			Route:    route,
			Domains:  cfg.Host.Domains,
			Fallback: nil,
			Resource: cfg.Resource,
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
		fallbackHandler = buildFallbackHandler(fallbackCfg, cfg.Resource.Logger)
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
		drainTimeout := woos.DefaultTransportDrainTimeout
		if h.global != nil && h.global.Timeouts.Read > 0 {
			drainTimeout = max(
				h.global.Timeouts.Read.StdDuration()+woos.DefaultTransportResponseHeaderTimeout,
				woos.DefaultTransportDrainTimeout,
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

func buildRouteLimiter(rlc *alaye.RouteRate, global *alaye.GlobalRate, ipMgr *zulu.IPManager, sharedState woos.SharedState) *ratelimit.RateLimiter {
	if rlc == nil || (!rlc.Enabled.Active() && rlc.UsePolicy == "") {
		return nil
	}
	ttl := woos.DefaultRateTTL
	maxEntries := woos.DefaultRateMaxEntries
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

// buildNonceStores creates one nonce.Store per replay rest endpoint that uses
// auth.method = "meta". Both the web handler (injection) and the serverless
// handler (consumption) receive the same store instances via this map.
func buildNonceStores(route *alaye.Route) map[string]*nonce.Store {
	stores := make(map[string]*nonce.Store)
	for _, r := range route.Serverless.Replay {
		if r.Enabled.Active() && r.IsReplayMode() && r.Auth.Enabled.Active() && r.Auth.Method == "meta" {
			stores[r.Name] = nonce.NewStore(0)
		}
	}
	return stores
}
