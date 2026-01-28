package handlers

import (
	"net/http"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/handlers/backend"
	"git.imaxinacion.net/aibox/agbero/internal/handlers/lb"
	"git.imaxinacion.net/aibox/agbero/internal/handlers/web"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/auth"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/compress"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/headers"
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
	chain := web.New(logger, route)

	var handler http.Handler = chain

	if route.BasicAuth != nil && len(route.BasicAuth.Users) > 0 {
		handler = auth.Basic(route.BasicAuth)(handler)
	}
	if route.ForwardAuth != nil && route.ForwardAuth.URL != "" {
		handler = auth.Forward(route.ForwardAuth)(handler)
	}

	if route.Headers != nil {
		handler = headers.Headers(route.Headers)(handler)
	}

	if route.CompressionConfig.Compression {
		handler = compress.Compress(route)(handler)
	}

	return &Route{
		handler:  handler,
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

	if route.BasicAuth != nil && len(route.BasicAuth.Users) > 0 {
		chain = auth.Basic(route.BasicAuth)(chain)
	}
	if route.ForwardAuth != nil && route.ForwardAuth.URL != "" {
		chain = auth.Forward(route.ForwardAuth)(chain)
	}
	if route.Headers != nil {
		chain = headers.Headers(route.Headers)(chain)
	}
	if route.CompressionConfig.Compression {
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
