package api

import (
	"encoding/json"
	"net/http"

	"git.imaxinacion.net/aibox/agbero/internal/cluster"
	"github.com/olekukonko/ll"
)

type Router struct {
	mux     *http.ServeMux
	cluster *cluster.Manager
	logger  *ll.Logger
}

func NewRouter(cluster *cluster.Manager, logger *ll.Logger, authMiddleware func(http.Handler) http.Handler) *Router {
	r := &Router{
		mux:     http.NewServeMux(),
		cluster: cluster,
		logger:  logger.Namespace("api"),
	}

	r.routes(authMiddleware)
	return r
}

func (ar *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ar.mux.ServeHTTP(w, r)
}

func (ar *Router) routes(authMiddleware func(http.Handler) http.Handler) {
	// Create the routes handler
	routesHandler := http.HandlerFunc(ar.handleRoutes)

	// Apply auth middleware - both sides are now http.Handler interface
	var handler http.Handler = routesHandler
	if authMiddleware != nil {
		handler = authMiddleware(handler)
	}

	ar.mux.Handle("/routes", handler)
}

// handleRoutes dispatches route management requests
func (ar *Router) handleRoutes(w http.ResponseWriter, r *http.Request) {
	if ar.cluster == nil {
		ar.errorResponse(w, http.StatusServiceUnavailable, "cluster mode disabled")
		return
	}

	switch r.Method {
	case http.MethodPost:
		ar.addRoute(w, r)
	case http.MethodDelete:
		ar.deleteRoute(w, r)
	default:
		ar.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (ar *Router) jsonResponse(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if data != nil {
		if err := json.NewEncoder(w).Encode(data); err != nil {
			ar.logger.Error("failed to encode api response", "err", err)
		}
	}
}

func (ar *Router) errorResponse(w http.ResponseWriter, code int, msg string) {
	ar.jsonResponse(w, code, map[string]string{"error": msg})
}
