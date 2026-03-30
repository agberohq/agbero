package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/olekukonko/ll"
)

// RevokeHandler registers the token revocation endpoint under /api/v1.
// This is an admin-only endpoint — it must be called inside the admin auth group.
func RevokeHandler(s *Shared, r chi.Router) {
	rv := &Revoke{shared: s, logger: s.Logger.Namespace("api/revoke")}
	r.Post("/auto/revoke", rv.revoke)
}

// Revoke handles admin requests to invalidate service tokens by JTI.
type Revoke struct {
	shared *Shared
	logger *ll.Logger
}

func (rv *Revoke) revoke(w http.ResponseWriter, r *http.Request) {
	if rv.shared.RevokeStore == nil {
		http.Error(w, `{"error":"revocation store not configured"}`, http.StatusNotImplemented)
		return
	}

	var req struct {
		JTI       string    `json:"jti"`
		Service   string    `json:"service"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json body"}`, http.StatusBadRequest)
		return
	}
	if req.JTI == "" {
		http.Error(w, `{"error":"jti is required"}`, http.StatusBadRequest)
		return
	}
	if req.ExpiresAt.IsZero() {
		http.Error(w, `{"error":"expires_at is required"}`, http.StatusBadRequest)
		return
	}
	if time.Now().After(req.ExpiresAt) {
		// Token already expired — nothing to revoke, treat as success.
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"message": "token already expired, no action needed",
		})
		return
	}

	if err := rv.shared.RevokeStore.Revoke(req.JTI, req.Service, req.ExpiresAt); err != nil {
		rv.logger.Fields("jti", req.JTI, "err", err).Error("failed to persist revocation")
		http.Error(w, `{"error":"failed to save revocation"}`, http.StatusInternalServerError)
		return
	}

	rv.logger.Fields("jti", req.JTI, "service", req.Service).Info("admin: token revoked")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
		"jti":    req.JTI,
	})
}
