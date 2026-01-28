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

type RouteHandler struct {
	handler  http.Handler
	Backends []*backend.Backend
}

func NewRouteHandler(route *alaye.Route, logger *ll.Logger) *RouteHandler {
	if route == nil {
		return FallbackRouteHandler("nil route")
	}

	if err := route.Validate(); err != nil {
		logger.Fields("path", route.Path, "err", err).Error("invalid route config")
		return FallbackRouteHandler("invalid route config")
	}

	if route.Web.Root.IsSet() {
		return newWebRouteHandler(route, logger)
	}

	return newProxyRouteHandler(route, logger)
}

func FallbackRouteHandler(msg string) *RouteHandler {
	return &RouteHandler{
		handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, msg, http.StatusBadGateway)
		}),
	}
}

func newWebRouteHandler(route *alaye.Route, logger *ll.Logger) *RouteHandler {
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

	return &RouteHandler{
		handler:  handler,
		Backends: nil,
	}
}

func newProxyRouteHandler(route *alaye.Route, logger *ll.Logger) *RouteHandler {
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

	return &RouteHandler{
		handler:  chain,
		Backends: backends,
	}
}

func (h *RouteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.handler == nil {
		http.Error(w, "route handler not initialized", http.StatusBadGateway)
		return
	}
	h.handler.ServeHTTP(w, r)
}

func (h *RouteHandler) Close() {
	for _, b := range h.Backends {
		b.Stop()
	}
}
