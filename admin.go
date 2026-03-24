package agbero

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"strconv"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/handlers/uptime"
	"github.com/agberohq/agbero/internal/middleware/auth"
	"github.com/agberohq/agbero/internal/middleware/ipallow"
	"github.com/agberohq/agbero/internal/middleware/ratelimit"
	"github.com/agberohq/agbero/internal/operation"
	"github.com/agberohq/agbero/internal/operation/api"
	"github.com/agberohq/agbero/internal/pkg/telemetry"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/bcrypt"
)

const (
	adminTokenTTL    = woos.AdminTokenTTL
	adminTokenIssuer = woos.AdminTokenIssuer
)

var dummyHash []byte

func init() {
	hash, _ := bcrypt.GenerateFromPassword([]byte("dummy-password-for-timing"), bcrypt.DefaultCost)
	dummyHash = hash
}

type adminClaims struct {
	User string `json:"user"`
	jwt.RegisteredClaims
}

// startAdminServer binds the admin HTTP server and registers it with the shutdown manager.
// The server is stored on s.adminSrv so it can be drained gracefully on process exit.
func (s *Server) startAdminServer() {
	if s.global.Admin.Enabled.NotActive() || s.global.Admin.Address == "" {
		return
	}

	cfg := s.global.Admin
	mux := http.NewServeMux()

	s.registerAdminHealthEndpoint(mux)
	s.registerAdminLoginEndpoint(mux)
	s.registerAdminLogoutEndpoint(mux)
	s.registerAdminAPI(mux)
	s.registerAdminProtectedEndpoints(mux, cfg)
	s.registerPprofEndpoints(mux, cfg)
	s.registerAdminUI(mux)

	ipMgr := zulu.NewIPManager(nil)
	adminRL := buildAdminRateLimiter(s.global, ipMgr, s.sharedState)
	finalHandler := s.wrapAdminMiddleware(mux, adminRL)

	s.adminSrv = &http.Server{
		Addr:         cfg.Address,
		Handler:      finalHandler,
		ReadTimeout:  woos.DefaultAdminReadTimeout,
		WriteTimeout: woos.DefaultAdminWriteTimeout,
		IdleTimeout:  woos.DefaultAdminIdleTimeout,
	}

	if s.shutdown != nil {
		s.shutdown.RegisterWithContext("AdminServer", func(ctx context.Context) error {
			return s.adminSrv.Shutdown(ctx)
		})
	}

	go func() {
		s.logger.Fields("bind", cfg.Address).Info("listener admin")
		if err := s.adminSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Fields("err", err).Error("admin server failed")
		}
	}()
}

// startPprofServer binds the standalone pprof HTTP server when configured.
// The server is stored on s.pprofSrv so it can be drained gracefully on process exit.
func (s *Server) startPprofServer() {
	if s.global.Admin.Pprof.Enabled.NotActive() || s.global.Admin.Pprof.Bind == "" {
		return
	}
	addr := s.global.Admin.Pprof.Bind
	if !strings.Contains(addr, ":") {
		addr = ":" + addr
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	mux.Handle("/debug/pprof/heap", pprof.Handler("heap"))
	mux.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
	mux.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate"))
	mux.Handle("/debug/pprof/block", pprof.Handler("block"))
	mux.Handle("/debug/pprof/mutex", pprof.Handler("mutex"))
	mux.Handle("/debug/pprof/allocs", pprof.Handler("allocs"))

	s.pprofSrv = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  woos.DefaultAdminReadTimeout,
		WriteTimeout: woos.DefaultAdminWriteTimeout,
		IdleTimeout:  woos.DefaultAdminIdleTimeout,
	}

	if s.shutdown != nil {
		s.shutdown.RegisterWithContext("PprofServer", func(ctx context.Context) error {
			return s.pprofSrv.Shutdown(ctx)
		})
	}

	go func() {
		s.logger.Fields("bind", addr).Warn("pprof listener started — do not expose publicly")
		if err := s.pprofSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Fields("err", err).Error("pprof server failed")
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

// registerAdminLogoutEndpoint exposes POST /logout which revokes the caller's JWT.
// The JTI is inserted into the in-memory revocation store and auto-expires via jtiLifetime.
func (s *Server) registerAdminLogoutEndpoint(mux *http.ServeMux) {
	mux.HandleFunc("/logout", s.handleLogout)
}

func (s *Server) registerAdminUI(mux *http.ServeMux) {
	mux.Handle("/", operation.Admin())
}

func (s *Server) registerAdminAPI(mux *http.ServeMux) {
	if s.clusterManager != nil && s.securityManager != nil {
		apiRouter := api.NewRouter(s.clusterManager, s.logger, auth.Internal(s.securityManager, s.logger))
		mux.Handle("/api/v1/", http.StripPrefix("/api/v1", apiRouter))
	} else if s.clusterManager == nil {
		s.logger.Warn("admin api disabled: cluster manager not active")
	} else if s.securityManager == nil {
		s.logger.Error("admin api disabled: security manager (internal_auth_key) not configured")
	}
}

func (s *Server) registerAdminProtectedEndpoints(mux *http.ServeMux, cfg alaye.Admin) {
	protect := s.buildAuthMiddleware(cfg)
	mux.Handle("/uptime", protect(uptime.Uptime(s.resource, s.hostManager, s.clusterManager, s.cookManager)))
	mux.Handle("/metrics", protect(promhttp.Handler()))
	mux.Handle("/config", protect(http.HandlerFunc(s.handleConfigDump)))
	mux.Handle("/logs", protect(http.HandlerFunc(s.handleLogs)))
	mux.Handle("/firewall", protect(http.HandlerFunc(s.handleFirewall)))
	mux.Handle("/api/hosts", protect(http.HandlerFunc(s.handleHostsAPI)))

	if s.global.Admin.Telemetry.Enabled.Active() && s.telemetryStore != nil {
		s.logger.Info("telemetry history enabled")
		mux.Handle("/telemetry/", protect(
			http.StripPrefix("/telemetry", telemetry.Handler(s.telemetryStore)),
		))
	}
}

// buildAuthMiddleware constructs the auth chain for protected admin endpoints.
// JWT issuer is always hardcoded to woos.AdminTokenIssuer regardless of operator config,
// preventing route-level tokens from being accepted on admin endpoints (SEC-05).
func (s *Server) buildAuthMiddleware(cfg alaye.Admin) func(http.Handler) http.Handler {
	ipMgr := zulu.NewIPManager(nil)
	return func(h http.Handler) http.Handler {
		if len(cfg.AllowedIPs) > 0 {
			h = ipallow.New(cfg.AllowedIPs, s.logger, ipMgr)(h)
		}
		if cfg.JWTAuth.Enabled.Active() {
			adminJWT := cfg.JWTAuth
			adminJWT.Issuer = woos.AdminTokenIssuer
			return auth.JWT(&adminJWT)(h)
		}
		if len(cfg.BasicAuth.Users) > 0 {
			return auth.Basic(&cfg.BasicAuth, s.logger)(h)
		}
		return h
	}
}

func (s *Server) registerPprofEndpoints(mux *http.ServeMux, cfg alaye.Admin) {
	if !cfg.Pprof.Enabled.Active() {
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

// wrapAdminMiddleware applies security headers and rate limiting to every admin response.
// The rate limiter is nil-safe; when no rules are configured it is skipped transparently.
func (s *Server) wrapAdminMiddleware(next http.Handler, rl *ratelimit.RateLimiter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline' blob: https://d3js.org; "+
				"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "+
				"font-src 'self' https://fonts.gstatic.com; "+
				"img-src 'self' data:; "+
				"connect-src 'self'; "+
				"frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		if rl != nil {
			rl.Handler(next).ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHostsAPI(w http.ResponseWriter, r *http.Request) {
	if s.hostManager == nil {
		http.Error(w, "Host manager not initialized", http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case http.MethodPost:
		var req struct {
			Domain string      `json:"domain"`
			Config *alaye.Host `json:"config"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}

		domain := strings.ToLower(strings.TrimSpace(req.Domain))
		if domain == "" {
			if req.Config != nil && len(req.Config.Domains) > 0 {
				domain = req.Config.Domains[0]
			} else {
				http.Error(w, "Domain is required", http.StatusBadRequest)
				return
			}
		}

		if strings.ContainsAny(domain, "/\\") || strings.Contains(domain, "..") {
			http.Error(w, "Invalid domain string", http.StatusBadRequest)
			return
		}

		if req.Config == nil {
			http.Error(w, "Config object is required", http.StatusBadRequest)
			return
		}

		if existingCfg := s.hostManager.Get(domain); existingCfg != nil {
			if existingCfg.Protected.Active() {
				http.Error(w, "Cannot modify host with protected routes via API", http.StatusForbidden)
				return
			}
		}

		req.Config.Domains = []string{domain}
		woos.DefaultHost(req.Config)

		if err := req.Config.Validate(); err != nil {
			http.Error(w, fmt.Sprintf("Configuration validation failed: %v", err), http.StatusBadRequest)
			return
		}

		if err := s.hostManager.Create(domain, req.Config); err != nil {
			s.logger.Fields("domain", domain, "err", err).Error("admin: failed to save host to disk")
			http.Error(w, "Failed to save configuration to disk", http.StatusInternalServerError)
			return
		}

		s.hostManager.Set(domain, req.Config)

		s.logger.Fields("domain", domain).Info("admin: host created/updated via api")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok", "message":"Host saved successfully"}`))

	case http.MethodDelete:
		domain := r.URL.Query().Get("domain")
		if domain == "" {
			http.Error(w, "Domain query parameter required", http.StatusBadRequest)
			return
		}

		if strings.ContainsAny(domain, "/\\") || strings.Contains(domain, "..") {
			http.Error(w, "Invalid domain string", http.StatusBadRequest)
			return
		}

		if existingCfg := s.hostManager.Get(domain); existingCfg != nil {
			if existingCfg.Protected.Active() {
				http.Error(w, "Cannot modify host with protected routes via API", http.StatusForbidden)
				return
			}
		}

		if err := s.hostManager.DeleteFile(domain); err != nil {
			s.logger.Fields("domain", domain, "err", err).Error("admin: failed to delete host file")
			http.Error(w, "Failed to delete host file", http.StatusInternalServerError)
			return
		}

		s.logger.Fields("domain", domain).Info("admin: host deleted via api")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok", "message":"Host deleted successfully"}`))

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

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
	})
}

// handleLogout revokes the JWT carried in the Authorization header by storing its JTI.
// The revocation entry auto-expires via jtiLifetime so the store never accumulates stale entries.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get(woos.AuthorizationHeaderKey)
	if authHeader == "" {
		w.WriteHeader(http.StatusOK)
		return
	}

	tokenStr := strings.TrimPrefix(authHeader, woos.HeaderKeyBearer+" ")

	s.mu.RLock()
	cfg := s.global.Admin
	s.mu.RUnlock()

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(cfg.JWTAuth.Secret.String()), nil
	})
	if err != nil || !token.Valid {
		w.WriteHeader(http.StatusOK)
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if jti, _ := claims["jti"].(string); jti != "" {
			exp := adminTokenTTL
			if expClaim, ok := claims["exp"].(float64); ok {
				if remaining := time.Until(time.Unix(int64(expClaim), 0)); remaining > 0 {
					exp = remaining
				}
			}
			s.jtiStore.SetTTL(jti, time.Now().Add(exp), exp)
			s.jtiLifetime.ScheduleTimed(r.Context(), jti, func(ctx context.Context, id string) {
				s.jtiStore.Delete(id)
			}, exp)
		}
	}

	w.WriteHeader(http.StatusOK)
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
				break
			}
		}
	}

	targetHash := foundHash
	if userFound == 0 {
		targetHash = dummyHash
	}
	return userFound == 1 && bcrypt.CompareHashAndPassword(targetHash, []byte(password)) == nil
}

// generateAdminToken mints a signed HS256 JWT for admin access.
// Each token carries a unique JTI so individual tokens can be revoked via POST /logout.
func (s *Server) generateAdminToken(username, secret string) (string, time.Time, error) {
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", time.Time{}, err
	}
	jti := hex.EncodeToString(jtiBytes)

	now := time.Now()
	expirationTime := now.Add(adminTokenTTL)
	claims := &adminClaims{
		User: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    adminTokenIssuer,
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
		resp.Cluster = map[string]any{
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
	if !isValidIPOrCIDR(req.IP) {
		http.Error(w, "Invalid IP address or CIDR", http.StatusBadRequest)
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
	if !isValidIPOrCIDR(ip) {
		http.Error(w, "Invalid IP address or CIDR", http.StatusBadRequest)
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
	limit := woos.DefaultAdminLogLimit
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
			if limit > woos.DefaultAdminLogMaxLimit {
				limit = woos.DefaultAdminLogMaxLimit
			}
		}
	}
	lines, err := readLastLogLines(logPath, limit)
	if err != nil {
		http.Error(w, "Error reading logs: "+err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if l != "" {
			out = append(out, l)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func isValidIPOrCIDR(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

func buildAdminRateLimiter(global *alaye.Global, ipMgr *zulu.IPManager, sharedState woos.SharedState) *ratelimit.RateLimiter {
	if global == nil || !global.RateLimits.Enabled.Active() || len(global.RateLimits.Rules) == 0 {
		return nil
	}
	rlc := global.RateLimits
	policy := func(r *http.Request) (bucket string, pol ratelimit.RatePolicy, ok bool) {
		p := r.URL.Path
		for _, rule := range rlc.Rules {
			if len(rule.Methods) > 0 {
				methodMatch := false
				for _, m := range rule.Methods {
					if strings.EqualFold(m, r.Method) {
						methodMatch = true
						break
					}
				}
				if !methodMatch {
					continue
				}
			}
			if len(rule.Prefixes) > 0 {
				prefixMatch := false
				for _, pref := range rule.Prefixes {
					if strings.HasPrefix(p, pref) {
						prefixMatch = true
						break
					}
				}
				if !prefixMatch {
					continue
				}
			}
			ruleName := rule.Name
			if ruleName == "" {
				ruleName = "admin_default"
			}
			return ruleName, ratelimit.RatePolicy{
				Requests: rule.Requests,
				Window:   rule.Window.StdDuration(),
				Burst:    rule.Burst,
				KeySpec:  rule.Key,
			}, true
		}
		return "", ratelimit.RatePolicy{}, false
	}
	ttl := woos.DefaultRateTTL
	maxEntries := woos.DefaultRateMaxEntries
	if rlc.TTL > 0 {
		ttl = rlc.TTL.StdDuration()
	}
	if rlc.MaxEntries > 0 {
		maxEntries = rlc.MaxEntries
	}
	return ratelimit.New(ratelimit.Config{
		TTL:         ttl,
		MaxEntries:  maxEntries,
		Policy:      policy,
		IPManager:   ipMgr,
		SharedState: sharedState,
	})
}
