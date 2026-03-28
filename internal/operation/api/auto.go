package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/discovery"
	"github.com/agberohq/agbero/internal/pkg/expect"
	"github.com/go-chi/chi/v5"
	"github.com/olekukonko/ll"
)

// AutoRouteHandler registers the service self-registration routes under /auto/v1.
// Unlike RouterHandler (admin), these routes scope DELETE to the calling service's
// own identity — a service may only deregister routes it registered itself.
func AutoRouteHandler(s *Shared, r chi.Router) {
	rt := NewAutoRoute(s)

	r.Group(func(r chi.Router) {
		r.Get("/ping", rt.ping)
		r.Post("/route", rt.addRoute)
		r.Delete("/route", rt.deleteRoute)
	})
}

type AutoRoute struct {
	shared *Shared
	logger *ll.Logger
}

func NewAutoRoute(cfg *Shared) *AutoRoute {
	return &AutoRoute{
		shared: cfg,
		logger: cfg.Logger.Namespace("api/auto"),
	}
}

// ping confirms the token is valid and returns the verified service identity.
// Useful for healthcheck and token validation without side effects.
func (rt *AutoRoute) ping(w http.ResponseWriter, r *http.Request) {
	serviceName := r.Header.Get(woos.HeaderXAgberoService)
	rt.jsonResponse(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": serviceName,
	})
}

func (rt *AutoRoute) addRoute(w http.ResponseWriter, r *http.Request) {
	if rt.shared.Cluster == nil {
		rt.errorResponse(w, http.StatusServiceUnavailable, "cluster mode disabled")
		return
	}

	var payload routePayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		rt.errorResponse(w, http.StatusBadRequest, "invalid json body")
		return
	}

	if err := payload.Validate(); err != nil {
		rt.errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	// Enforce that the host matches the service identity from the token.
	// auth.Internal sets X-Agbero-Service after verifying the PPK token.
	serviceName := r.Header.Get(woos.HeaderXAgberoService)
	if err := enforceServiceScope(serviceName, payload.Host); err != nil {
		rt.logger.Fields("service", serviceName, "host", payload.Host).Warn("auto: scope violation on register")
		rt.errorResponse(w, http.StatusForbidden, err.Error())
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
	rt.shared.Cluster.BroadcastRoute(key, val)

	rt.logger.Fields("service", serviceName, "key", key).Info("auto: route registered")
	rt.jsonResponse(w, http.StatusOK, map[string]string{
		"status": "ok",
		"key":    key,
	})
}

func (rt *AutoRoute) deleteRoute(w http.ResponseWriter, r *http.Request) {
	if rt.shared.Cluster == nil {
		rt.errorResponse(w, http.StatusServiceUnavailable, "cluster mode disabled")
		return
	}

	h := expect.New(r.URL.Query().Get("host"))
	host, err := h.Domain()
	if err != nil {
		rt.errorResponse(w, http.StatusBadRequest, "host parameter is required")
		return
	}

	p := expect.New(r.URL.Query().Get("path"))
	path, _ := p.Path()
	if path == "" {
		path = "/"
	}

	// A service may only deregister its own routes.
	serviceName := r.Header.Get(woos.HeaderXAgberoService)
	if err := enforceServiceScope(serviceName, host); err != nil {
		rt.logger.Fields("service", serviceName, "host", host).Warn("auto: scope violation on deregister")
		rt.errorResponse(w, http.StatusForbidden, err.Error())
		return
	}

	key := fmt.Sprintf("%s%s|%s", discovery.ClusterRoutePrefix, host, path)
	rt.shared.Cluster.Delete(key)

	rt.logger.Fields("service", serviceName, "key", key).Info("auto: route deregistered")
	rt.jsonResponse(w, http.StatusOK, map[string]string{
		"status": "deleted",
		"key":    key,
	})
}

// enforceServiceScope verifies that the requesting service is only operating
// on routes scoped to its own identity. The convention is that the host must
// contain the service name as a prefix segment, e.g. a service named
// "auth-service" may register "auth-service-host1.internal" but not
// "other-service.internal".
func enforceServiceScope(serviceName, host string) error {
	if serviceName == "" {
		return fmt.Errorf("service identity missing from token")
	}
	if host == "" {
		return fmt.Errorf("host is required")
	}
	// The host must begin with the service name to ensure a service can only
	// register routes under its own identity namespace.
	if !hasServicePrefix(host, serviceName) {
		return fmt.Errorf("host %q is not within service scope %q", host, serviceName)
	}
	return nil
}

// hasServicePrefix checks whether host begins with serviceName followed by
// a separator ("-" or "."), preventing "auth" from matching "auth-evil".
func hasServicePrefix(host, serviceName string) bool {
	if len(host) <= len(serviceName) {
		return false
	}
	if host[:len(serviceName)] != serviceName {
		return false
	}
	sep := host[len(serviceName)]
	return sep == '-' || sep == '.'
}

func (rt *AutoRoute) errorResponse(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (rt *AutoRoute) jsonResponse(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if data != nil {
		if err := json.NewEncoder(w).Encode(data); err != nil {
			rt.logger.Error("failed to encode response", "err", err)
		}
	}
}
