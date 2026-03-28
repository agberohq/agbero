package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/agberohq/agbero/internal/cluster"
	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/discovery"
	"github.com/agberohq/agbero/internal/pkg/expect"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/go-chi/chi/v5"
	"github.com/olekukonko/ll"
)

// RouterHandler registers all route management API endpoints directly on the provided chi.Router.
// It wires POST and DELETE methods to dedicated handlers on the Route instance.
func RouterHandler(s *Shared, r chi.Router) {
	rt := NewRoute(s)

	r.Group(func(r chi.Router) {
		r.Post("/route", rt.addRoute)
		r.Delete("/route", rt.deleteRoute)
	})
}

// routePayload defines the expected JSON body for route registration requests.
// It includes host, route definition, and optional TTL for automatic expiration.
type routePayload struct {
	Host       string      `json:"host"`
	Route      alaye.Route `json:"route"`
	TTLSeconds int         `json:"ttl_seconds"`
}

func (r routePayload) Validate() error {

	h := expect.New(r.Host)
	host, err := h.Domain()
	if err != nil {
		return fmt.Errorf("invalid host: %w", err)
	}
	r.Host = host

	if r.Route.Path == "" {
		r.Route.Path = "/"
	}

	p := expect.New(r.Route.Path)
	path, err := p.Path()
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}
	r.Route.Path = path

	if r.TTLSeconds < 0 {
		return fmt.Errorf("TTL cannot be negative")
	}
	if r.TTLSeconds > 31536000 {
		return fmt.Errorf("TTL cannot exceed 31536000 seconds (1 year)")
	}

	return nil
}

// Route provides HTTP handlers for dynamic route registration and expiration management.
// It interacts with the cluster store to persist route metadata with optional TTL.
type Route struct {
	cluster *cluster.Manager
	store   *security.Store
	logger  *ll.Logger
}

// NewRoute initializes a Route instance with shared application dependencies.
// It configures the logger namespace for consistent API-level logging.
func NewRoute(cfg *Shared) *Route {
	return &Route{
		cluster: cfg.Cluster,
		store:   cfg.Store,
		logger:  cfg.Logger.Namespace("api"),
	}
}

// addRoute handles POST requests to register a new route with optional expiration TTL.
// It validates payload, wraps route with metadata, and stores it in the cluster KV.
func (rt *Route) addRoute(w http.ResponseWriter, r *http.Request) {
	var payload routePayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		rt.errorResponse(w, http.StatusBadRequest, "invalid json body")
		return
	}

	err := payload.Validate()
	if err != nil {
		rt.errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}
	wrapper := discovery.ClusterRouteWrapper{
		Route: payload.Route,
	}

	if payload.TTLSeconds > 0 {
		wrapper.ExpiresAt = time.Now().Add(time.Duration(payload.TTLSeconds) * time.Second)
	}

	val, err := json.Marshal(wrapper)
	if err != nil {
		rt.errorResponse(w, http.StatusInternalServerError, "failed to serialize route")
		return
	}

	key := fmt.Sprintf("%s%s|%s", discovery.ClusterRoutePrefix, payload.Host, payload.Route.Path)
	rt.cluster.BroadcastRoute(key, val)

	rt.jsonResponse(w, http.StatusOK, map[string]string{
		"status": "ok",
		"key":    key,
	})
}

// deleteRoute handles DELETE requests to remove a registered route from the cluster store.
// It constructs the storage key from query params and emits a delete operation.
func (rt *Route) deleteRoute(w http.ResponseWriter, r *http.Request) {
	h := expect.New(r.URL.Query().Get("host"))
	p := expect.New(r.URL.Query().Get("path"))

	host, err := h.Domain()
	if err != nil {
		rt.errorResponse(w, http.StatusBadRequest, "host parameter is required")
		return
	}

	path, err := p.Path()
	if path == "" {
		path = "/"
	}

	key := fmt.Sprintf("%s%s|%s", discovery.ClusterRoutePrefix, host, path)
	rt.cluster.Delete(key)

	rt.jsonResponse(w, http.StatusOK, map[string]string{
		"status": "deleted",
		"key":    key,
	})
}

// errorResponse sends a standardized JSON error response with HTTP status and message.
// It ensures consistent error formatting across all route API endpoints.
func (rt *Route) errorResponse(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// jsonResponse encodes and sends a JSON response with the provided status code and data.
// It logs encoding errors internally without exposing them to the client.
func (rt *Route) jsonResponse(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if data != nil {
		if err := json.NewEncoder(w).Encode(data); err != nil {
			rt.logger.Error("failed to encode response", "err", err)
		}
	}
}
