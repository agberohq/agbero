package agbero

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/pprof"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/handlers/uptime"
	"github.com/agberohq/agbero/internal/middleware/auth"
	"github.com/agberohq/agbero/internal/operation"
	"github.com/agberohq/agbero/internal/operation/api"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/bcrypt"
)

// =============================================================================
// Constants and Initialization
// =============================================================================

var dummyHash []byte

func init() {
	hash, _ := bcrypt.GenerateFromPassword([]byte("dummy-password-for-timing"), bcrypt.DefaultCost)
	dummyHash = hash
}

// =============================================================================
// JWT Claims
// =============================================================================

type adminClaims struct {
	User string `json:"user"`
	jwt.RegisteredClaims
}

func (s *Server) startAdminServer() {
	if s.global.Admin.Enabled.NotActive() || s.global.Admin.Address == "" {
		return
	}

	cfg := s.global.Admin
	mux := http.NewServeMux()

	s.registerAdminHealthEndpoint(mux)
	s.registerAdminLoginEndpoint(mux)
	s.registerAdminAPI(mux)
	s.registerAdminProtectedEndpoints(mux, cfg)
	s.registerPprofEndpoints(mux, cfg)

	s.registerAdminUI(mux)

	finalHandler := s.wrapAdminMiddleware(mux)

	srv := &http.Server{
		Addr:         cfg.Address,
		Handler:      finalHandler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		s.logger.Fields("bind", cfg.Address).Info("listener admin")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Fields("err", err).Error("admin server failed")
		}
	}()
}

func (s *Server) registerAdminHealthEndpoint(mux *http.ServeMux) {
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
}

func (s *Server) registerAdminLoginEndpoint(mux *http.ServeMux) {
	mux.HandleFunc("/login", s.handleLogin)
}

func (s *Server) registerAdminUI(mux *http.ServeMux) {
	uiHandler := operation.Admin()
	mux.Handle("/", uiHandler)
}

func (s *Server) registerAdminAPI(mux *http.ServeMux) {
	if s.clusterManager != nil && s.securityManager != nil {
		apiRouter := api.NewRouter(s.clusterManager, s.logger, auth.Internal(s.securityManager, s.logger))
		mux.Handle("/api/v1/", http.StripPrefix("/api/v1", apiRouter))
	} else if s.clusterManager == nil {
		s.logger.Warn("admin api disabled: cluster manager not active")
	} else if s.securityManager == nil {
		s.logger.Warn("admin api disabled: security manager (internal_auth_key) not configured")
	}
}

func (s *Server) registerAdminProtectedEndpoints(mux *http.ServeMux, cfg alaye.Admin) {
	protect := s.buildAuthMiddleware(cfg)

	mux.Handle("/uptime", protect(uptime.Uptime(s.resource, s.hostManager, s.clusterManager, s.cookManager)))
	mux.Handle("/metrics", protect(promhttp.Handler()))
	mux.Handle("/config", protect(http.HandlerFunc(s.handleConfigDump)))
	mux.Handle("/logs", protect(http.HandlerFunc(s.handleLogs)))
	mux.Handle("/firewall", protect(http.HandlerFunc(s.handleFirewall)))
}

func (s *Server) buildAuthMiddleware(cfg alaye.Admin) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		if cfg.JWTAuth.Enabled.Active() {
			return auth.JWT(&cfg.JWTAuth)(h)
		}
		if len(cfg.BasicAuth.Users) > 0 {
			return auth.Basic(&cfg.BasicAuth)(h)
		}
		return h
	}
}

func (s *Server) registerPprofEndpoints(mux *http.ServeMux, cfg alaye.Admin) {
	if !cfg.Pprof.Active() {
		return
	}

	s.logger.Warn("pprof debugging enabled on admin interface")

	protect := s.buildAuthMiddleware(cfg)

	mux.Handle("/debug/pprof/", protect(http.HandlerFunc(pprof.Index)))
	mux.Handle("/debug/pprof/cmdline", protect(http.HandlerFunc(pprof.Cmdline)))
	mux.Handle("/debug/pprof/profile", protect(http.HandlerFunc(pprof.Profile)))
	mux.Handle("/debug/pprof/symbol", protect(http.HandlerFunc(pprof.Symbol)))
	mux.Handle("/debug/pprof/trace", protect(http.HandlerFunc(pprof.Trace)))

	mux.Handle("/debug/pprof/heap", protect(pprof.Handler("heap")))
	mux.Handle("/debug/pprof/goroutine", protect(pprof.Handler("goroutine")))
	mux.Handle("/debug/pprof/threadcreate", protect(pprof.Handler("threadcreate")))
	mux.Handle("/debug/pprof/block", protect(pprof.Handler("block")))
	mux.Handle("/debug/pprof/mutex", protect(pprof.Handler("mutex")))
	mux.Handle("/debug/pprof/allocs", protect(pprof.Handler("allocs")))
}

// wrapAdminMiddleware wraps the entire mux to apply security headers
func (s *Server) wrapAdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/") {
			w.Header().Set("Content-Security-Policy",
				"default-src 'self'; "+
					"script-src 'self' https://d3js.org; "+
					"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "+
					"font-src 'self' https://fonts.gstatic.com; "+
					"img-src 'self' data:; "+
					"connect-src 'self'; "+
					"frame-ancestors 'none'")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		}
		next.ServeHTTP(w, r)
	})
}

// =============================================================================
// Request Handlers
// =============================================================================

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	cfg := s.global.Admin
	s.mu.RUnlock()

	if !cfg.BasicAuth.Enabled.Active() || len(cfg.BasicAuth.Users) == 0 {
		http.Error(w, "Server Config Error: Unknown admin users defined in 'basic_auth'", http.StatusForbidden)
		return
	}

	if !cfg.JWTAuth.Enabled.Active() || cfg.JWTAuth.Secret == "" {
		http.Error(w, "Server Config Error: 'jwt_auth.secret' is required for login", http.StatusForbidden)
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

	if !s.verifyCredentials(cfg.BasicAuth.Users, creds.Username, creds.Password) {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	tokenString, expirationTime, err := s.generateAdminToken(creds.Username, cfg.JWTAuth.Secret.String())
	if err != nil {
		s.logger.Error("Failed to sign admin token: ", err)
		http.Error(w, "Internal Signing Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token":   tokenString,
		"expires": expirationTime.Format(time.RFC3339),
		"user":    creds.Username,
	})
}

func (s *Server) verifyCredentials(users []string, username, password string) bool {
	var foundHash []byte
	userFound := 0
	inputUserHash := sha256.Sum256([]byte(username))

	for _, u := range users {
		parts := strings.SplitN(u, ":", 2)
		if len(parts) == 2 {
			storedUserHash := sha256.Sum256([]byte(parts[0]))
			if subtle.ConstantTimeCompare(inputUserHash[:], storedUserHash[:]) == 1 {
				foundHash = []byte(parts[1])
				userFound = 1
			}
		}
	}

	targetHash := foundHash
	if userFound == 0 {
		targetHash = dummyHash
	}

	err := bcrypt.CompareHashAndPassword(targetHash, []byte(password))
	return userFound == 1 && err == nil
}

func (s *Server) generateAdminToken(username, secret string) (string, time.Time, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &adminClaims{
		User: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			Issuer:    "agbero-admin",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	return tokenString, expirationTime, err
}

func (s *Server) handleConfigDump(w http.ResponseWriter, r *http.Request) {
	hosts, _ := s.hostManager.LoadAll()

	resp := struct {
		Global  any `json:"global"`
		Hosts   any `json:"hosts"`
		Cluster any `json:"cluster,omitempty"`
	}{
		Global: sanitizeGlobalConfig(s.global),
		Hosts:  sanitizeHostConfigs(hosts),
	}

	if s.clusterManager != nil {
		resp.Cluster = map[string]interface{}{
			"members": s.clusterManager.Members(),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleFirewall(w http.ResponseWriter, r *http.Request) {
	if s.firewall == nil {
		s.handleFirewallDisabled(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleFirewallList(w)
	case http.MethodPost:
		s.handleFirewallBlock(w, r)
	case http.MethodDelete:
		s.handleFirewallUnblock(w, r)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleFirewallDisabled(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"enabled": false,
			"rules":   []string{},
		})
		return
	}
	http.Error(w, "firewall is disabled in configuration", http.StatusNotImplemented)
}

func (s *Server) handleFirewallList(w http.ResponseWriter) {
	rules, err := s.firewall.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"enabled": true,
		"rules":   rules,
	})
}

func (s *Server) handleFirewallBlock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP          string `json:"ip"`
		Reason      string `json:"reason"`
		Host        string `json:"host"`
		Path        string `json:"path"`
		DurationSec int    `json:"duration_sec"`
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
	reason := s.buildBlockReason(req.Reason, req.Host, req.Path)

	if err := s.firewall.Block(req.IP, reason, dur); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.logger.Fields("ip", req.IP, "reason", reason, "duration", dur).Info("admin: blocked ip")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Blocked"))
}

func (s *Server) buildBlockReason(reason, host, path string) string {
	var details []string
	if host != "" {
		details = append(details, "host="+host)
	}
	if path != "" {
		details = append(details, "path="+path)
	}
	if len(details) > 0 {
		return fmt.Sprintf("%s (%s)", reason, strings.Join(details, ", "))
	}
	return reason
}

func (s *Server) handleFirewallUnblock(w http.ResponseWriter, r *http.Request) {
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
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	var logPath string
	if s.global.Logging.File.Enabled.Active() {
		logPath = s.global.Logging.File.Path
	}

	if logPath == "" {
		http.Error(w, "File logging disabled", http.StatusNotImplemented)
		return
	}

	limit := 50
	lines, err := readLastLogLines(logPath, limit)
	if err != nil {
		http.Error(w, "Error reading logs: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var logs []map[string]any
	for _, l := range lines {
		if l == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(l), &entry); err == nil {
			logs = append(logs, entry)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}
