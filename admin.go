package agbero

import (
	"encoding/json"
	"net/http"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/handlers/metrics"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/auth"
)

func (s *Server) startAdminServer() {
	if s.global.Admin == nil || s.global.Admin.Address == "" {
		return
	}

	cfg := s.global.Admin
	mux := http.NewServeMux()

	// Metrics
	mux.HandleFunc("/metrics", metrics.Metrics(s.hostManager))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Firewall Management API
	if s.firewall != nil {
		mux.HandleFunc("/firewall", s.handleFirewallAPI)
	}

	var handler http.Handler = mux

	// Apply Admin Authentication
	if cfg.BasicAuth != nil && len(cfg.BasicAuth.Users) > 0 {
		handler = auth.Basic(cfg.BasicAuth)(handler)
	}
	if cfg.ForwardAuth != nil && cfg.ForwardAuth.URL != "" {
		handler = auth.Forward(cfg.ForwardAuth)(handler)
	}

	srv := &http.Server{
		Addr:         cfg.Address,
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	go func() {
		s.logger.Fields("bind", cfg.Address).Info("admin server starting")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Fields("err", err).Error("admin server failed")
		}
	}()
}

// handleFirewallAPI manages IP blocks via API
// GET: List rules
// POST: Block IP (JSON: {ip, reason, duration_sec})
// DELETE: Unblock IP (Query: ?ip=...)
func (s *Server) handleFirewallAPI(w http.ResponseWriter, r *http.Request) {
	if s.firewall == nil {
		http.Error(w, "Firewall disabled", http.StatusNotImplemented)
		return
	}

	switch r.Method {
	case http.MethodGet:
		rules, err := s.firewall.List()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rules)

	case http.MethodPost:
		var req struct {
			IP          string `json:"ip"`
			Reason      string `json:"reason"`
			DurationSec int    `json:"duration_sec"` // 0 = permanent
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		if req.IP == "" {
			http.Error(w, "IP required", http.StatusBadRequest)
			return
		}

		dur := time.Duration(req.DurationSec) * time.Second
		if err := s.firewall.Block(req.IP, req.Reason, dur); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.logger.Fields("ip", req.IP, "reason", req.Reason, "duration", dur).Info("admin: blocked ip")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Blocked"))

	case http.MethodDelete:
		ip := r.URL.Query().Get("ip")
		if ip == "" {
			http.Error(w, "IP query parameter required", http.StatusBadRequest)
			return
		}
		if err := s.firewall.Unblock(ip); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.logger.Fields("ip", ip).Info("admin: unblocked ip")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Unblocked"))

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}
