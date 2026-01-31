package agbero

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/handlers/metrics"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/auth"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/ipallow"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// AdminClaims defines the JWT structure for Admin access
type AdminClaims struct {
	User string `json:"user"`
	jwt.RegisteredClaims
}

func (s *Server) startAdminServer() {
	if s.global.Admin == nil || s.global.Admin.Address == "" {
		return
	}

	cfg := s.global.Admin
	mux := http.NewServeMux()

	// --- 1. Public Endpoints ---

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Login Handler: Exchanges BasicAuth credentials for a JWT.
	// This allows the UI to work with a token even if BasicAuth is configured backing store.
	mux.HandleFunc("/login", s.handleAdminLogin)

	// --- 2. Protected Endpoints ---

	// Metrics
	mux.HandleFunc("/metrics", metrics.Metrics(s.hostManager))

	// Config Dump (Sanitized)
	mux.HandleFunc("/config", s.handleAdminConfigDump)

	// Firewall Management API
	if s.firewall != nil {
		mux.HandleFunc("/firewall", s.handleFirewallAPI)
	}

	// --- 3. Middleware Chain Construction ---
	// Order: IPAllow -> OAuth -> JWT -> Basic -> Forward -> Handler

	var handler http.Handler = mux

	//  IP Restriction (Gatekeeper - First Line of Defense)
	if len(cfg.AllowedIPs) > 0 {
		handler = ipallow.New(cfg.AllowedIPs, s.logger)(handler)
	}

	// Layer A: Forward Auth (External)
	if cfg.ForwardAuth != nil && cfg.ForwardAuth.URL != "" {
		handler = auth.Forward(cfg.ForwardAuth)(handler)
	}

	// Layer B: Basic Auth (Traditional)
	if cfg.BasicAuth != nil && len(cfg.BasicAuth.Users) > 0 {
		handler = auth.Basic(cfg.BasicAuth)(handler)
	}

	// Layer C: JWT Auth (API / UI Token)
	if cfg.JWTAuth != nil {
		handler = auth.JWT(cfg.JWTAuth)(handler)
	}

	// Layer D: OAuth (Browser / SSO)
	if cfg.OAuth != nil {
		handler = auth.OAuth(cfg.OAuth)(handler)
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

// handleAdminLogin authenticates against configured BasicAuth users and issues a JWT.
func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg := s.global.Admin

	// We need BasicAuth users to verify credentials
	if cfg.BasicAuth == nil || len(cfg.BasicAuth.Users) == 0 {
		http.Error(w, "No admin users configured", http.StatusForbidden)
		return
	}

	// We need JWTAuth config to sign the token
	if cfg.JWTAuth == nil || cfg.JWTAuth.Secret == "" {
		http.Error(w, "JWT signing secret not configured", http.StatusForbidden)
		return
	}

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Verify Creds
	found := false
	for _, u := range cfg.BasicAuth.Users {
		// Format "user:hash"
		parts := strings.SplitN(u, ":", 2)
		if len(parts) == 2 && parts[0] == creds.Username {
			if err := bcrypt.CompareHashAndPassword([]byte(parts[1]), []byte(creds.Password)); err == nil {
				found = true
				break
			}
		}
	}

	if !found {
		// Fake delay to prevent timing attacks
		time.Sleep(100 * time.Millisecond)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Generate Token
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &AdminClaims{
		User: creds.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			Issuer:    "agbero-admin",
		},
	}

	// Use secret from JWTAuth config
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(cfg.JWTAuth.Secret.String()))
	if err != nil {
		http.Error(w, "Internal Signing Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token":   tokenString,
		"expires": expirationTime.Format(time.RFC3339),
	})
}

// handleAdminConfigDump returns a sanitized JSON dump of the running configuration.
func (s *Server) handleAdminConfigDump(w http.ResponseWriter, r *http.Request) {
	// 1. Get Host Snapshot
	hosts, _ := s.hostManager.LoadAll()

	// 2. Sanitize
	safeGlobal := sanitizeGlobal(s.global)
	safeHosts := sanitizeHosts(hosts)

	resp := struct {
		Global any `json:"global"`
		Hosts  any `json:"hosts"`
	}{
		Global: safeGlobal,
		Hosts:  safeHosts,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// --- Sanitization Helpers ---

func sanitizeGlobal(g *alaye.Global) *alaye.Global {
	b, _ := json.Marshal(g)
	var clone alaye.Global
	_ = json.Unmarshal(b, &clone)

	// Scrub Secrets
	if clone.Gossip.SecretKey != "" {
		clone.Gossip.SecretKey = "******"
	}
	if clone.Gossip.PrivateKeyFile != "" {
		clone.Gossip.PrivateKeyFile = "******"
	}

	if clone.Admin != nil {
		if clone.Admin.BasicAuth != nil {
			clone.Admin.BasicAuth.Users = []string{"****** (hidden)"}
		}
		if clone.Admin.JWTAuth != nil {
			clone.Admin.JWTAuth.Secret = "******"
		}
		if clone.Admin.OAuth != nil {
			clone.Admin.OAuth.ClientSecret = "******"
			clone.Admin.OAuth.CookieSecret = "******"
		}
	}

	return &clone
}

func sanitizeHosts(hosts map[string]*alaye.Host) map[string]*alaye.Host {
	out := make(map[string]*alaye.Host)
	for k, v := range hosts {
		b, _ := json.Marshal(v)
		var clone alaye.Host
		_ = json.Unmarshal(b, &clone)

		for i := range clone.Routes {
			if clone.Routes[i].BasicAuth != nil {
				clone.Routes[i].BasicAuth.Users = []string{"******"}
			}
			if clone.Routes[i].JWTAuth != nil {
				clone.Routes[i].JWTAuth.Secret = "******"
			}
			if clone.Routes[i].OAuth != nil {
				clone.Routes[i].OAuth.ClientSecret = "******"
				clone.Routes[i].OAuth.CookieSecret = "******"
			}
			if clone.Routes[i].ForwardAuth != nil {
				// URL might be considered sensitive if internal, but usually kept
			}
		}
		out[k] = &clone
	}
	return out
}

// handleFirewallAPI manages IP blocks via API
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
