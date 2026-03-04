package handlers

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"git.imaxinacion.net/aibox/agbero/internal/handlers/xhttp"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/attic"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/auth"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/compress"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/cors"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/errorpages"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/headers"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/ipallow"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/ratelimit"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/rewrite"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/metrics"
	"git.imaxinacion.net/aibox/agbero/internal/ui"
	"github.com/olekukonko/ll"
)

type Route struct {
	handler  http.Handler
	Backends []*xhttp.Backend
}

// NewRoute updated to accept domains
func NewRoute(global *alaye.Global, host *alaye.Host, route *alaye.Route, logger *ll.Logger) *Route {
	if route == nil {
		return FallbackRoute("nil route")
	}

	// ensure to apply default again
	woos.DefaultRoute(route)

	logger.Fields("path", route.Path, "enabled", route.Enabled).Debug("creating route")
	if err := route.Validate(); err != nil {
		logger.Fields("path", route.Path, "err", err).Error("invalid route config")
		return FallbackRoute("invalid route config: " + err.Error())
	}

	isWebRoute := route.Web.Root.IsSet()
	hasBackends := len(route.Backends.Servers) > 0

	if isWebRoute && hasBackends {
		return FallbackRoute("route cannot have both web and proxy config")
	}

	if isWebRoute {
		return newWebRoute(global, host, route, logger)
	}
	if hasBackends {
		return newProxyRoute(global, host, route, logger)
	}

	return FallbackRoute("route has no handler configuration")
}

func newWebRoute(global *alaye.Global, host *alaye.Host, route *alaye.Route, logger *ll.Logger) *Route {
	chain := http.Handler(ui.NewWeb(logger, route))

	if len(route.AllowedIPs) > 0 {
		chain = ipallow.New(route.AllowedIPs, logger)(chain)
	}

	chain = auth.JWT(&route.JWTAuth)(chain)
	chain = auth.Basic(&route.BasicAuth)(chain)
	chain = auth.Forward(&route.ForwardAuth)(chain)
	chain = auth.OAuth(&route.OAuth)(chain)

	if rl := buildRouteLimiter(&route.RateLimit, &global.RateLimits); rl != nil {
		chain = rl.Handler(chain)
	}

	chain = headers.Headers(&route.Headers)(chain)
	chain = compress.Compress(route)(chain)

	// Cache
	chain = attic.New(&route.Cache, logger)(chain)

	// Error Pages
	errCfg := errorpages.Config{
		RoutePages:  route.ErrorPages,
		HostPages:   host.ErrorPages,
		GlobalPages: global.ErrorPages,
	}
	chain = errorpages.New(errCfg)(chain)

	chain = cors.New(&route.CORS)(chain)
	chain = rewrite.New(logger, route.StripPrefixes, route.Rewrites)(chain)

	return &Route{handler: chain, Backends: nil}
}

// newProxyRoute updated to pass domains
func newProxyRoute(global *alaye.Global, host *alaye.Host, route *alaye.Route, logger *ll.Logger) *Route {
	var backends []*xhttp.Backend
	for i, backendCfg := range route.Backends.Servers {
		b, err := xhttp.NewBackend(backendCfg, route, host.Domains, logger, metrics.DefaultRegistry)
		if err != nil {
			logger.Fields("index", i, "backend", backendCfg.Address, "err", err).Error("failed to create backend")
			continue
		}
		backends = append(backends, b)
	}

	fallbackCfg := resolveFallback(&route.Fallback, &global.Fallback)
	var fallbackHandler http.Handler
	if fallbackCfg.IsActive() {
		fallbackHandler = buildFallbackHandler(fallbackCfg, logger)
	}

	if len(backends) == 0 {
		if fallbackHandler != nil {
			return &Route{handler: fallbackHandler, Backends: nil}
		}
		return FallbackRoute("proxy route missing backends")
	}

	timeout := time.Duration(0)
	if route.Timeouts.Request != 0 {
		timeout = route.Timeouts.Request
	}

	balancerCfg := xhttp.Config{
		Strategy: route.Backends.Strategy,
		Timeout:  timeout,
		Fallback: fallbackHandler,
	}

	loadBalancer := xhttp.NewBalancer(balancerCfg, backends)

	var chain http.Handler = loadBalancer

	if len(route.AllowedIPs) > 0 {
		chain = ipallow.New(route.AllowedIPs, logger)(chain)
	}

	chain = auth.JWT(&route.JWTAuth)(chain)
	chain = auth.Basic(&route.BasicAuth)(chain)
	chain = auth.Forward(&route.ForwardAuth)(chain)
	chain = auth.OAuth(&route.OAuth)(chain)

	if rl := buildRouteLimiter(&route.RateLimit, &global.RateLimits); rl != nil {
		chain = rl.Handler(chain)
	}

	chain = headers.Headers(&route.Headers)(chain)
	chain = compress.Compress(route)(chain)

	// Cache
	chain = attic.New(&route.Cache, logger)(chain)

	// Error Pages
	errCfg := errorpages.Config{
		RoutePages:  route.ErrorPages,
		HostPages:   host.ErrorPages,
		GlobalPages: global.ErrorPages,
	}
	chain = errorpages.New(errCfg)(chain)

	chain = cors.New(&route.CORS)(chain)
	chain = rewrite.New(logger, route.StripPrefixes, route.Rewrites)(chain)

	return &Route{handler: chain, Backends: backends}
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

func (h *Route) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.handler == nil {
		http.Error(w, "route handler not initialized", http.StatusBadGateway)
		return
	}
	h.handler.ServeHTTP(w, r)
}

func (h *Route) Close() {
	for _, b := range h.Backends {
		if b != nil {
			b.Stop()
		}
	}
}

func FallbackRoute(msg string) *Route {
	return &Route{
		handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, msg, http.StatusBadGateway)
		}),
	}
}

func buildRouteLimiter(rlc *alaye.RouteRate, global *alaye.GlobalRate) *ratelimit.RateLimiter {
	if rlc == nil {
		return nil
	}
	if !rlc.Enabled.Active() && rlc.UsePolicy == "" {
		return nil
	}
	ttl := 30 * time.Minute
	maxEntries := int64(100_000)
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
		if strings.HasPrefix(path, "/.well-known/acme-challenge/") {
			return "", ratelimit.RatePolicy{}, false
		}
		for _, rule := range rules {
			if len(rule.Methods) > 0 {
				methodMatch := slices.Contains(rule.Methods, r.Method)
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
	return ratelimit.NewRateLimiter(ttl, maxEntries, policy)
}
