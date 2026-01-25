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
	// The final handler in the chain (Load Balancer)
	// wrapped by middlewares.
	handler http.Handler

	// Internal access needed for "Close" and Metrics
	Backends []*backend.Backend
}

func NewRouteHandler(route *alaye.Route, logger *ll.Logger) *RouteHandler {
	if route == nil {
		logger.Error("nil route")
		return nil
	}

	// Validate route semantics first (web XOR backends, required fields, etc.)
	if err := route.Validate(); err != nil {
		logger.Fields("path", route.Path, "err", err).Error("invalid route config")
		return nil
	}

	logger.Fields("path", route.Path, "web_root_raw", string(route.Web.Root), "backends", route.Backends).
		Debug("creating route handler")

	// At this point route.Validate() guaranteed exactly one of these:
	// - web route with root set
	// - proxy route with backends set
	if route.Web.Root.IsSet() {
		logger.Debug("treating as WEB route")
		return newWebRouteHandler(route, logger)
	}

	logger.Debug("treating as PROXY route")
	return newProxyRouteHandler(route, logger)
}

func newWebRouteHandler(route *alaye.Route, logger *ll.Logger) *RouteHandler {
	// Web route doesn't need backends or load balancing
	chain := web.New(logger, route)

	// Build middleware chain (same as proxy routes)
	var handler http.Handler = chain

	// Authentication
	if route.BasicAuth != nil && len(route.BasicAuth.Users) > 0 {
		handler = auth.Basic(route.BasicAuth)(handler)
	}
	if route.ForwardAuth != nil && route.ForwardAuth.URL != "" {
		handler = auth.Forward(route.ForwardAuth)(handler)
	}

	// Headers
	if route.Headers != nil {
		handler = headers.Headers(route.Headers)(handler)
	}

	// Compression
	if route.CompressionConfig.Compression {
		handler = compress.Compress(route)(handler)
	}

	return &RouteHandler{
		handler:  handler,
		Backends: nil, // No backends for web routes
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
		Backends: backends, // for Close() / metrics only
	}
}

func (h *RouteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.handler.ServeHTTP(w, r)
}

func (h *RouteHandler) Close() {
	for _, b := range h.Backends {
		b.Stop()
	}
}
