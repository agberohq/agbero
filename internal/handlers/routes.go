package handlers

import (
	"net/http"
	"strings"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core"
	"git.imaxinacion.net/aibox/agbero/internal/handlers/backend"
	"git.imaxinacion.net/aibox/agbero/internal/handlers/lb"
	"git.imaxinacion.net/aibox/agbero/internal/handlers/web"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/auth"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/compress"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/headers"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/ipallow"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/ratelimit"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/ll"
)

type Route struct {
	handler  http.Handler
	Backends []*backend.Backend
}

func NewRoute(route *alaye.Route, logger *ll.Logger) *Route {
	if route == nil {
		return FallbackRoute("nil route")
	}

	if err := route.Validate(); err != nil {
		logger.Fields("path", route.Path, "err", err).Error("invalid route config")
		return FallbackRoute("invalid route config")
	}

	if route.Web.Root.IsSet() {
		return newWebRoute(route, logger)
	}

	return newProxyRoute(route, logger)
}

func newWebRoute(route *alaye.Route, logger *ll.Logger) *Route {
	chain := http.Handler(web.New(logger, route))

	// Check if IP address is allowed
	if len(route.AllowedIPs) > 0 {
		chain = ipallow.New(route.AllowedIPs, logger)(chain)
	}

	if route.JWTAuth != nil {
		chain = auth.JWT(route.JWTAuth)(chain)
	}
	if route.BasicAuth != nil && len(route.BasicAuth.Users) > 0 {
		chain = auth.Basic(route.BasicAuth)(chain)
	}
	if route.ForwardAuth != nil && route.ForwardAuth.URL != "" {
		chain = auth.Forward(route.ForwardAuth)(chain)
	}

	if route.RateLimit != nil && route.RateLimit.Enabled {
		if rl := buildRouteLimiter(route.RateLimit); rl != nil {
			chain = rl.Handler(chain)
		}
	}

	if route.Headers != nil {
		chain = headers.Headers(route.Headers)(chain)
	}

	if route.CompressionConfig.Enabled {
		chain = compress.Compress(route)(chain)
	}

	return &Route{
		handler:  chain,
		Backends: nil,
	}
}

func newProxyRoute(route *alaye.Route, logger *ll.Logger) *Route {
	var backends []*backend.Backend

	for _, backendCfg := range route.Backends.Servers {
		b, err := backend.NewBackend(backendCfg, route, logger)
		if err != nil {
			logger.Fields("backend", backendCfg.Address, "err", err).
				Error("failed to create backend")
			continue
		}
		backends = append(backends, b)
	}

	timeout := time.Duration(0)
	if route.Timeouts != nil && route.Timeouts.Request != 0 {
		timeout = route.Timeouts.Request
	}

	loadBalancer := lb.NewLoadBalancer(
		backends,
		route.Backends.LBStrategy,
		timeout,
		route.StripPrefixes,
	)

	var chain http.Handler = loadBalancer

	// Check if IP address is allowed
	if len(route.AllowedIPs) > 0 {
		chain = ipallow.New(route.AllowedIPs, logger)(chain)
	}

	if route.JWTAuth != nil {
		chain = auth.JWT(route.JWTAuth)(chain)
	}
	if route.BasicAuth != nil && len(route.BasicAuth.Users) > 0 {
		chain = auth.Basic(route.BasicAuth)(chain)
	}
	if route.ForwardAuth != nil && route.ForwardAuth.URL != "" {
		chain = auth.Forward(route.ForwardAuth)(chain)
	}

	if route.RateLimit != nil && route.RateLimit.Enabled {
		if rl := buildRouteLimiter(route.RateLimit); rl != nil {
			chain = rl.Handler(chain)
		}
	}

	if route.Headers != nil {
		chain = headers.Headers(route.Headers)(chain)
	}
	if route.CompressionConfig.Enabled {
		chain = compress.Compress(route)(chain)
	}

	return &Route{
		handler:  chain,
		Backends: backends,
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
		b.Stop()
	}
}

func FallbackRoute(msg string) *Route {
	return &Route{
		handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, msg, http.StatusBadGateway)
		}),
	}
}

func buildRouteLimiter(rlc *alaye.Rate) *ratelimit.RateLimiter {
	if rlc == nil || !rlc.Enabled || len(rlc.Rules) == 0 {
		return nil
	}

	ttl := core.Or(rlc.TTL, 30*time.Minute)
	maxEntries := rlc.MaxEntries
	if maxEntries <= 0 {
		maxEntries = 100_000
	}

	policy := func(r *http.Request) (bucket string, pol ratelimit.RatePolicy, ok bool) {
		path := r.URL.Path
		if strings.HasPrefix(path, "/.well-known/acme-challenge/") {
			return "", ratelimit.RatePolicy{}, false
		}

		for _, rule := range rlc.Rules {
			// 1. Check Method
			if len(rule.Methods) > 0 {
				methodMatch := false
				for _, m := range rule.Methods {
					if m == r.Method {
						methodMatch = true
						break
					}
				}
				if !methodMatch {
					continue
				}
			}

			// 2. Check Prefix
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

			// Match Found
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
