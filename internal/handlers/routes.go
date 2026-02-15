package handlers

import (
	"net/http"
	"strings"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/metrics"
	"git.imaxinacion.net/aibox/agbero/internal/handlers/xhttp"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/auth"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/compress"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/headers"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/ipallow"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/ratelimit"
	"git.imaxinacion.net/aibox/agbero/internal/ui"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/ll"
)

type Route struct {
	handler  http.Handler
	Backends []*xhttp.Backend
}

func NewRoute(route *alaye.Route, globalRate *alaye.GlobalRate, logger *ll.Logger) *Route {
	if route == nil {
		return FallbackRoute("nil route")
	}

	if err := route.Validate(); err != nil {
		logger.Fields("path", route.Path, "err", err).Error("invalid route config")
		return FallbackRoute("invalid route config")
	}

	if route.Web.Root.IsSet() {
		return newWebRoute(route, globalRate, logger)
	}

	return newProxyRoute(route, globalRate, logger)
}

func newWebRoute(route *alaye.Route, globalRate *alaye.GlobalRate, logger *ll.Logger) *Route {
	chain := http.Handler(ui.NewWeb(logger, route))

	if len(route.AllowedIPs) > 0 {
		chain = ipallow.New(route.AllowedIPs, logger)(chain)
	}

	if route.JWTAuth.Enabled.Yes() {
		chain = auth.JWT(&route.JWTAuth)(chain)
	}
	if route.BasicAuth.Enabled.Yes() && len(route.BasicAuth.Users) > 0 {
		chain = auth.Basic(&route.BasicAuth)(chain)
	}
	if route.ForwardAuth.Enabled.Yes() && route.ForwardAuth.URL != "" {
		chain = auth.Forward(&route.ForwardAuth)(chain)
	}

	if route.RateLimit.Enabled.Yes() {
		if rl := buildRouteLimiter(&route.RateLimit, globalRate); rl != nil {
			chain = rl.Handler(chain)
		}
	}

	if route.Headers.Enabled.Yes() {
		chain = headers.Headers(&route.Headers)(chain)
	}

	if route.CompressionConfig.Enabled.Yes() {
		chain = compress.Compress(route)(chain)
	}

	return &Route{
		handler:  chain,
		Backends: nil,
	}
}

func newProxyRoute(route *alaye.Route, globalRate *alaye.GlobalRate, logger *ll.Logger) *Route {
	var backends []*xhttp.Backend

	//  Defensive check for Backends
	if route.Backends.Enabled.No() {
		// If no backends and not a web route, this is a misconfiguration or a placeholder route.
		// We return a fallback to avoid panic.
		logger.Fields("path", route.Path).Warn("proxy route has no backends configured")
		return FallbackRoute("proxy route missing backends")
	}

	for _, backendCfg := range route.Backends.Servers {
		b, err := xhttp.NewBackend(backendCfg, route, logger, metrics.DefaultRegistry)
		if err != nil {
			logger.Fields("backend", backendCfg.Address, "err", err).
				Error("failed to create backend")
			continue
		}
		backends = append(backends, b)
	}

	timeout := time.Duration(0)
	if route.Timeouts.Request != 0 {
		timeout = route.Timeouts.Request
	}

	loadBalancer := xhttp.NewBalancer(
		backends,
		route.Backends.Strategy,
		timeout,
		route.StripPrefixes,
	)

	var chain http.Handler = loadBalancer

	if len(route.AllowedIPs) > 0 {
		chain = ipallow.New(route.AllowedIPs, logger)(chain)
	}

	if route.JWTAuth.Enabled.Yes() {
		chain = auth.JWT(&route.JWTAuth)(chain)
	}
	if route.BasicAuth.Enabled.Yes() && len(route.BasicAuth.Users) > 0 {
		chain = auth.Basic(&route.BasicAuth)(chain)
	}
	if route.ForwardAuth.Enabled.Yes() && route.ForwardAuth.URL != "" {
		chain = auth.Forward(&route.ForwardAuth)(chain)
	}

	if route.RateLimit.Enabled.Yes() && route.RateLimit.Enabled.Yes() {
		if rl := buildRouteLimiter(&route.RateLimit, globalRate); rl != nil {
			chain = rl.Handler(chain)
		}
	}

	if route.Headers.Enabled.Yes() {
		chain = headers.Headers(&route.Headers)(chain)
	}
	if route.CompressionConfig.Enabled.Yes() {
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

func buildRouteLimiter(rlc *alaye.RouteRate, global *alaye.GlobalRate) *ratelimit.RateLimiter {
	if rlc == nil || !rlc.Enabled.Yes() {
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

	if rlc.Rule.Enabled.Yes() {
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
