package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
)

// ClusterRouteWrapper wraps the route with expiration metadata
type ClusterRouteWrapper struct {
	Route     alaye.Route `json:"route"`
	ExpiresAt time.Time   `json:"expires_at"`
}

type routePayload struct {
	Host       string      `json:"host"`
	Route      alaye.Route `json:"route"`
	TTLSeconds int         `json:"ttl_seconds"`
}

func (ar *Router) addRoute(w http.ResponseWriter, r *http.Request) {
	var payload routePayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		ar.errorResponse(w, http.StatusBadRequest, "invalid json body")
		return
	}

	if payload.Host == "" {
		ar.errorResponse(w, http.StatusBadRequest, "host is required")
		return
	}

	if payload.Route.Path == "" {
		payload.Route.Path = "/"
	}
	if !strings.HasPrefix(payload.Route.Path, "/") {
		ar.errorResponse(w, http.StatusBadRequest, "path must start with /")
		return
	}

	wrapper := ClusterRouteWrapper{
		Route: payload.Route,
	}

	if payload.TTLSeconds > 0 {
		wrapper.ExpiresAt = time.Now().Add(time.Duration(payload.TTLSeconds) * time.Second)
	}

	val, err := json.Marshal(wrapper)
	if err != nil {
		ar.errorResponse(w, http.StatusInternalServerError, "failed to serialize route")
		return
	}

	key := fmt.Sprintf("%s%s|%s", discovery.ClusterRoutePrefix, payload.Host, payload.Route.Path)
	ar.cluster.Set(key, val)

	ar.jsonResponse(w, http.StatusOK, map[string]string{
		"status": "ok",
		"key":    key,
	})
}

func (ar *Router) deleteRoute(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	path := r.URL.Query().Get("path")

	if host == "" {
		ar.errorResponse(w, http.StatusBadRequest, "host parameter is required")
		return
	}

	if path == "" {
		path = "/"
	}

	key := fmt.Sprintf("%s%s|%s", discovery.ClusterRoutePrefix, host, path)

	// We check if it exists via Get (optional, but good for feedback)
	// Cluster Set/Delete are async/eventual, so we just emit the delete op.
	ar.cluster.Delete(key)

	ar.jsonResponse(w, http.StatusOK, map[string]string{
		"status": "deleted",
		"key":    key,
	})
}
