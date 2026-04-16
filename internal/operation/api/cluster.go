package api

import (
	"encoding/json"
	"net/http"

	"github.com/agberohq/agbero/internal/hub/cluster"
	"github.com/agberohq/keeper"
	"github.com/go-chi/chi/v5"
	"github.com/olekukonko/ll"
)

// ClusterHandler registers all cluster API routes directly on the provided chi.Router.
// It wires HTTP methods to dedicated handler functions on the Cluster instance.
func ClusterHandler(s *Shared, r chi.Router) {
	c := NewCluster(s)

	r.Group(func(r chi.Router) {
		r.Post("/cluster", c.addRoute)
		r.Delete("/cluster", c.deleteRoute)
	})
}

// Cluster provides HTTP handlers for cluster route management operations.
// It encapsulates dependencies for logging, security, and cluster coordination.
type Cluster struct {
	cluster *cluster.Manager
	store   *keeper.Keeper
	logger  *ll.Logger
}

// NewCluster initializes a Cluster instance with shared application dependencies.
// It configures the logger namespace and prepares middleware for request handling.
func NewCluster(cfg *Shared) *Cluster {
	return &Cluster{
		cluster: cfg.Cluster,
		store:   cfg.Keeper,
		logger:  cfg.Logger.Namespace("api"),
	}
}

// addRoute handles POST requests to register a new route in the cluster.
// It validates the request payload, delegates to the cluster ppk, and returns JSON.
func (c *Cluster) addRoute(w http.ResponseWriter, r *http.Request) {
	if c.cluster == nil {
		c.errorResponse(w, http.StatusServiceUnavailable, "cluster mode disabled")
		return
	}

	var req struct {
		Host string `json:"host"`
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.errorResponse(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	if req.Host == "" {
		c.errorResponse(w, http.StatusBadRequest, "host is required")
		return
	}

	key := "route:" + req.Host + req.Path
	value, _ := json.Marshal(req)
	c.cluster.BroadcastRoute(key, value)

	c.logger.Fields("host", req.Host, "path", req.Path).Info("cluster route added")
	c.jsonResponse(w, http.StatusOK, map[string]string{"status": "route added"})
}

// deleteRoute handles DELETE requests to remove an existing route from the cluster.
// It validates the request payload, delegates to the cluster ppk, and returns JSON.
func (c *Cluster) deleteRoute(w http.ResponseWriter, r *http.Request) {
	if c.cluster == nil {
		c.errorResponse(w, http.StatusServiceUnavailable, "cluster mode disabled")
		return
	}

	var req struct {
		Host string `json:"host"`
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.errorResponse(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	if req.Host == "" {
		c.errorResponse(w, http.StatusBadRequest, "host is required")
		return
	}

	key := "route:" + req.Host + req.Path
	c.cluster.Delete(key)

	c.logger.Fields("host", req.Host, "path", req.Path).Info("cluster route deleted")
	c.jsonResponse(w, http.StatusOK, map[string]string{"status": "route deleted"})
}

// errorResponse sends a standardized JSON error response with HTTP status and message.
// It ensures consistent error formatting across all cluster API endpoints.
func (c *Cluster) errorResponse(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// jsonResponse encodes and sends a JSON response with the provided status code and data.
// It logs encoding errors internally without exposing them to the client.
func (c *Cluster) jsonResponse(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if data != nil {
		if err := json.NewEncoder(w).Encode(data); err != nil {
			c.logger.Error("failed to encode response", "err", err)
		}
	}
}
