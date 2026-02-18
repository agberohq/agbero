package agbero

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/pprof"
	"os"
	"strings"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/handlers/uptime"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/auth"
	"git.imaxinacion.net/aibox/agbero/internal/ui"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/bcrypt"
)

var (
	dummyHash []byte
)

func init() {
	hash, _ := bcrypt.GenerateFromPassword([]byte("dummy-password-for-timing"), bcrypt.DefaultCost)
	dummyHash = hash
}

// AdminClaims defines the JWT structure for Admin access
type AdminClaims struct {
	User string `json:"user"`
	jwt.RegisteredClaims
}

func (s *Server) startAdminServer() {
	if s.global.Admin.Enabled.NotActive() || s.global.Admin.Address == "" {
		return
	}

	cfg := s.global.Admin
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	mux.HandleFunc("/login", s.handleAdminLogin)

	uiHandler := ui.Admin()
	mux.Handle("/", uiHandler)

	// protect enforces the primary API authentication method (usually JWT).
	// This prevents browser popups on the dashboard if the token expires.
	protect := func(h http.Handler) http.Handler {
		if cfg.JWTAuth.Enabled.Active() {
			return auth.JWT(&cfg.JWTAuth)(h)
		}
		if len(cfg.BasicAuth.Users) > 0 {
			return auth.Basic(&cfg.BasicAuth)(h)
		}
		return h
	}

	// protectBasic enforces Basic Auth specifically for pprof.
	// This ensures browsers prompt for credentials when accessing debug tools directly.
	protectBasic := func(h http.Handler) http.Handler {
		if len(cfg.BasicAuth.Users) > 0 {
			return auth.Basic(&cfg.BasicAuth)(h)
		}
		// Fallback to JWT for CLI tools if Basic Auth is not configured
		if cfg.JWTAuth.Enabled.Active() {
			return auth.JWT(&cfg.JWTAuth)(h)
		}
		return h
	}

	mux.Handle("/uptime", protect(uptime.Uptime(s.hostManager)))
	mux.Handle("/metrics", protect(promhttp.Handler()))
	mux.Handle("/config", protect(http.HandlerFunc(s.handleAdminConfigDump)))
	mux.Handle("/logs", protect(http.HandlerFunc(s.handleAdminLogs)))
	mux.Handle("/firewall", protect(http.HandlerFunc(s.handleFirewallAPI)))

	if cfg.Pprof.Active() {
		s.logger.Warn("pprof debugging enabled on admin interface")

		mux.Handle("/debug/pprof/", protectBasic(http.HandlerFunc(pprof.Index)))
		mux.Handle("/debug/pprof/cmdline", protectBasic(http.HandlerFunc(pprof.Cmdline)))
		mux.Handle("/debug/pprof/profile", protectBasic(http.HandlerFunc(pprof.Profile)))
		mux.Handle("/debug/pprof/symbol", protectBasic(http.HandlerFunc(pprof.Symbol)))
		mux.Handle("/debug/pprof/trace", protectBasic(http.HandlerFunc(pprof.Trace)))

		mux.Handle("/debug/pprof/heap", protectBasic(pprof.Handler("heap")))
		mux.Handle("/debug/pprof/goroutine", protectBasic(pprof.Handler("goroutine")))
		mux.Handle("/debug/pprof/threadcreate", protectBasic(pprof.Handler("threadcreate")))
		mux.Handle("/debug/pprof/block", protectBasic(pprof.Handler("block")))
		mux.Handle("/debug/pprof/mutex", protectBasic(pprof.Handler("mutex")))
		mux.Handle("/debug/pprof/allocs", protectBasic(pprof.Handler("allocs")))
	}

	// Wrap the mux with the middleware for setting security headers.
	// Standard http.ServeMux lacks a Use method, so chain manually.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/admin") {
			w.Header().Set("Content-Security-Policy",
				"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
					"img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		}
		mux.ServeHTTP(w, r)
	})

	srv := &http.Server{
		Addr:         cfg.Address,
		Handler:      handler, // Use the wrapped handler.
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

// handleAdminLogin verifies credentials against agbero.hcl > admin > basic_auth > users
func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
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

	var foundHash []byte
	userFound := 0
	inputUserHash := sha256.Sum256([]byte(creds.Username))
	for _, u := range cfg.BasicAuth.Users {
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

	err := bcrypt.CompareHashAndPassword(targetHash, []byte(creds.Password))
	if userFound == 0 || err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &AdminClaims{
		User: creds.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			Issuer:    "agbero-admin",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(cfg.JWTAuth.Secret.String()))
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

// handleAdminConfigDump returns a sanitized JSON dump of the running configuration.
func (s *Server) handleAdminConfigDump(w http.ResponseWriter, r *http.Request) {
	hosts, _ := s.hostManager.LoadAll()

	resp := struct {
		Global any `json:"global"`
		Hosts  any `json:"hosts"`
	}{
		Global: sanitizeGlobal(s.global),
		Hosts:  sanitizeHosts(hosts),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleFirewallAPI manages IP blocks via API
func (s *Server) handleFirewallAPI(w http.ResponseWriter, r *http.Request) {
	if s.firewall == nil {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"enabled": false,
				"rules":   []string{},
			})
			return
		}
		http.Error(w, "firewall is disabled in configuration", http.StatusNotImplemented)
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
		json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled": true,
			"rules":   rules,
		})

	case http.MethodPost:
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

		reason := req.Reason
		var details []string
		if req.Host != "" {
			details = append(details, "host="+req.Host)
		}
		if req.Path != "" {
			details = append(details, "path="+req.Path)
		}
		if len(details) > 0 {
			reason = fmt.Sprintf("%s (%s)", reason, strings.Join(details, ", "))
		}

		if err := s.firewall.Block(req.IP, reason, dur); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.logger.Fields("ip", req.IP, "reason", reason, "duration", dur).Info("admin: blocked ip")
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

// handleAdminLogs reads the log file backwards efficiently
func (s *Server) handleAdminLogs(w http.ResponseWriter, r *http.Request) {
	var logPath string
	if s.global.Logging.Enabled.Active() {
		logPath = s.global.Logging.File
	}

	if logPath == "" {
		http.Error(w, "File logging disabled", http.StatusNotImplemented)
		return
	}

	limit := 50
	lines, err := readLastLines(logPath, limit)
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

func sanitizeGlobal(g *alaye.Global) *alaye.Global {
	b, _ := json.Marshal(g)
	var clone alaye.Global
	_ = json.Unmarshal(b, &clone)

	if clone.Gossip.Enabled.Active() {
		clone.Gossip.SecretKey = "***"
		clone.Gossip.PrivateKeyFile = "***"
	}

	if clone.Admin.Enabled.Active() {
		if clone.Admin.BasicAuth.Enabled.Active() {
			for i := range clone.Admin.BasicAuth.Users {
				clone.Admin.BasicAuth.Users[i] = "***"
			}
		}
		if clone.Admin.JWTAuth.Enabled.Active() {
			clone.Admin.JWTAuth.Secret = "***"
		}
		if clone.Admin.ForwardAuth.Enabled.Active() {
			clone.Admin.ForwardAuth.URL = "***"
		}
		if clone.Admin.OAuth.Enabled.Active() {
			clone.Admin.OAuth.ClientSecret = "***"
			clone.Admin.OAuth.CookieSecret = "***"
		}
	}

	if clone.Security.Enabled.Active() {
		for i := range clone.Security.TrustedProxies {
			clone.Security.TrustedProxies[i] = "***"
		}
	}

	if clone.LetsEncrypt.Enabled.Active() {
		clone.LetsEncrypt.Email = "***"
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
			if clone.Routes[i].BasicAuth.Enabled.Active() {
				for j := range clone.Routes[i].BasicAuth.Users {
					clone.Routes[i].BasicAuth.Users[j] = "***"
				}
			}
			if clone.Routes[i].JWTAuth.Enabled.Active() {
				clone.Routes[i].JWTAuth.Secret = "***"
			}
			if clone.Routes[i].OAuth.Enabled.Active() {
				clone.Routes[i].OAuth.ClientSecret = "***"
				clone.Routes[i].OAuth.CookieSecret = "***"
			}
			if clone.Routes[i].Wasm.Enabled.Active() && len(clone.Routes[i].Wasm.Config) > 0 {
				clone.Routes[i].Wasm.Config = map[string]string{"***": "***"}
			}
			if clone.Routes[i].ForwardAuth.Enabled.Active() {
				clone.Routes[i].ForwardAuth.URL = "***"
			}
		}
		out[k] = &clone
	}
	return out
}

func readLastLines(filename string, n int) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}

	fileSize := stat.Size()
	var lines []string

	const bufSize = 1024
	buf := make([]byte, bufSize)

	var offset int64 = fileSize
	var leftover string

	for offset > 0 && len(lines) < n {
		readSize := int64(bufSize)
		if offset < readSize {
			readSize = offset
		}
		offset -= readSize

		_, err := file.Seek(offset, io.SeekStart)
		if err != nil {
			return nil, err
		}

		_, err = file.Read(buf[:readSize])
		if err != nil {
			return nil, err
		}

		chunk := string(buf[:readSize]) + leftover
		parts := strings.Split(chunk, "\n")

		if offset > 0 {
			leftover = parts[0]
			parts = parts[1:]
		}

		for i := len(parts) - 1; i >= 0; i-- {
			line := strings.TrimSpace(parts[i])
			if line != "" {
				lines = append(lines, line)
				if len(lines) >= n {
					break
				}
			}
		}
	}

	return lines, nil
}
