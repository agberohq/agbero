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
	mtrand "math/rand"
	"net/http"
	"net/http/pprof"
	"strconv"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/handlers/uptime"
	"github.com/agberohq/agbero/internal/hub/secrets"
	"github.com/agberohq/agbero/internal/middleware/auth"
	"github.com/agberohq/agbero/internal/middleware/ipallow"
	"github.com/agberohq/agbero/internal/middleware/ratelimit"
	"github.com/agberohq/agbero/internal/operation"
	"github.com/agberohq/agbero/internal/operation/api"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/olekukonko/zero"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/bcrypt"
)

const (
	adminTokenTTL        = woos.AdminTokenTTL
	adminTokenIssuer     = woos.AdminTokenIssuer
	challengeTokenTTL    = 5 * time.Minute
	challengeTokenIssuer = "agbero-challenge"
)

var (
	dummyHash       []byte
	challengeSecret = make([]byte, 32)
)

func init() {
	p := security.NewPassword()
	dummyHash = p.Dummy()
	rand.Read(challengeSecret)
}

type adminClaims struct {
	User  string `json:"user"`
	Scope string `json:"scope,omitempty"`
	jwt.RegisteredClaims
}

func (s *Server) startAdminServer() {
	state := s.apiShared.State()
	if state.Global.Admin.Enabled.NotActive() || state.Global.Admin.Address == "" {
		return
	}

	r := chi.NewRouter()

	s.setupAdminMiddleware(r, state.Global.Admin)
	s.registerAdminRoutes(r, state.Global.Admin)

	s.mu.Lock()
	s.adminSrv = &http.Server{
		Addr:         state.Global.Admin.Address,
		Handler:      r,
		ReadTimeout:  woos.DefaultAdminReadTimeout,
		WriteTimeout: woos.DefaultAdminWriteTimeout,
		IdleTimeout:  woos.DefaultAdminIdleTimeout,
	}
	s.mu.Unlock()

	if s.shutdown != nil {
		s.shutdown.RegisterWithContext("AdminServer", func(ctx context.Context) error {
			return s.adminSrv.Shutdown(ctx)
		})
	}

	go func() {
		s.logger.Fields("bind", state.Global.Admin.Address).Info("listener admin")
		if err := s.adminSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Fields("err", err).Error("admin server failed")
		}
	}()
}

func (s *Server) startPprofServer() {
	state := s.apiShared.State()
	if state.Global.Admin.Pprof.Enabled.NotActive() || state.Global.Admin.Pprof.Bind == "" {
		return
	}
	addr := state.Global.Admin.Pprof.Bind
	if !strings.Contains(addr, ":") {
		addr = ":" + addr
	}

	r := chi.NewRouter()
	r.HandleFunc("/debug/pprof/", pprof.Index)
	r.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	r.HandleFunc("/debug/pprof/profile", pprof.Profile)
	r.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	r.HandleFunc("/debug/pprof/trace", pprof.Trace)
	r.Handle("/debug/pprof/heap", pprof.Handler("heap"))
	r.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
	r.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate"))
	r.Handle("/debug/pprof/block", pprof.Handler("block"))
	r.Handle("/debug/pprof/mutex", pprof.Handler("mutex"))
	r.Handle("/debug/pprof/allocs", pprof.Handler("allocs"))

	s.mu.Lock()
	s.pprofSrv = &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  woos.DefaultAdminReadTimeout,
		WriteTimeout: woos.DefaultAdminWriteTimeout,
		IdleTimeout:  woos.DefaultAdminIdleTimeout,
	}
	s.mu.Unlock()

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

func (s *Server) setupAdminMiddleware(r chi.Router, cfg alaye.Admin) {
	r.Use(func(next http.Handler) http.Handler {
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
			next.ServeHTTP(w, r)
		})
	})

	ipMgr := zulu.NewIPManager(nil)
	state := s.apiShared.State()
	adminRL := buildAdminRateLimiter(state.Global, ipMgr, s.sharedState)
	if adminRL != nil {
		r.Use(adminRL.Handler)
	}
}

func (s *Server) registerAdminRoutes(r chi.Router, cfg alaye.Admin) {
	r.Get("/healthz", s.handleHealthz)
	r.Get("/status", s.handleStatus)
	r.Post("/login", s.handleLogin)
	r.Post("/login/challenge", s.handleLoginChallenge)
	r.Post("/logout", s.handleLogout)

	r.Group(func(r chi.Router) {
		r.Use(s.buildAuthMiddleware(cfg))
		r.Post("/refresh", s.handleRefresh)
		r.Get("/uptime", uptime.Uptime(s.resource, s.hostManager, s.clusterManager, s.cookManager).ServeHTTP)
		r.Handle("/metrics", promhttp.Handler())
		r.Route("/config", func(r chi.Router) {
			r.Get("/", s.handleConfigDump)
			r.Get("/global", s.handleConfigGlobal)
			r.Get("/hosts", s.handleConfigHosts)
		})
		r.Get("/logs", s.handleLogs)

		api.AdminHandler(s.apiShared, r)

		if cfg.Pprof.Enabled.Active() {
			s.logger.Warn("pprof debugging enabled on admin interface")
			r.HandleFunc("/debug/pprof/", pprof.Index)
			r.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
			r.HandleFunc("/debug/pprof/profile", pprof.Profile)
			r.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
			r.HandleFunc("/debug/pprof/trace", pprof.Trace)
			r.Handle("/debug/pprof/heap", pprof.Handler("heap"))
			r.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
			r.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate"))
			r.Handle("/debug/pprof/block", pprof.Handler("block"))
			r.Handle("/debug/pprof/mutex", pprof.Handler("mutex"))
			r.Handle("/debug/pprof/allocs", pprof.Handler("allocs"))
		}
	})

	if s.apiShared.PPK != nil {
		r.Group(func(r chi.Router) {
			var isRevoked func(string) bool
			if s.apiShared.RevokeStore != nil {
				isRevoked = s.apiShared.RevokeStore.IsRevoked
			}
			r.Use(auth.Internal(s.apiShared.PPK, s.logger, isRevoked))
			api.AutoHandler(s.apiShared, r)
		})
	} else {
		s.logger.Warn("auto api disabled: internal_auth_key not configured")
	}

	r.Mount("/", operation.Admin())
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	state := s.apiShared.State()

	status := map[string]any{
		"status":    "ok",
		"auth":      true,
		"telemetry": state.Global.Admin.Telemetry.Enabled.Active(),
	}

	authState := "ready"

	var challenges []string
	if s.keeperStore != nil && s.keeperStore.IsLocked() {
		challenges = append(challenges, "keeper_unlock")
	}
	if state.Global.Admin.TOTP.Enabled.Active() {
		challenges = append(challenges, "totp")
	}
	if len(challenges) > 0 {
		authState = "challenge_required"
		status["challenges"] = challenges
	}

	status["auth_state"] = authState

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(status)
}

func (s *Server) buildAuthMiddleware(cfg alaye.Admin) func(http.Handler) http.Handler {
	ipMgr := zulu.NewIPManager(nil)
	isRevoked := func(jti string) bool {
		_, revoked := s.resource.TimeStore.Get(jti)
		return revoked
	}

	return func(next http.Handler) http.Handler {
		authHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get(woos.AuthorizationHeaderKey)
			if authHeader == "" {
				http.Error(w, `{"error":"missing_authorization"}`, http.StatusUnauthorized)
				return
			}

			tokenStr := strings.TrimPrefix(authHeader, woos.HeaderKeyBearer+" ")

			parser := new(jwt.Parser)
			unverifiedToken, _, err := parser.ParseUnverified(tokenStr, &adminClaims{})
			if err != nil {
				http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
				return
			}

			claims, ok := unverifiedToken.Claims.(*adminClaims)
			if !ok || claims.User == "" {
				http.Error(w, `{"error":"invalid_claims"}`, http.StatusUnauthorized)
				return
			}

			jwtSecret, err := s.getAdminJWTSecret(claims.User)
			if err != nil {
				http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
				return
			}

			token, err := jwt.ParseWithClaims(tokenStr, &adminClaims{}, func(token *jwt.Token) (any, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method")
				}
				return []byte(jwtSecret), nil
			})

			if err != nil || !token.Valid {
				http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
				return
			}

			validClaims, ok := token.Claims.(*adminClaims)
			if !ok {
				http.Error(w, `{"error":"invalid_claims"}`, http.StatusUnauthorized)
				return
			}

			if validClaims.Issuer != woos.AdminTokenIssuer {
				http.Error(w, `{"error":"invalid_issuer"}`, http.StatusUnauthorized)
				return
			}

			if validClaims.Scope == "challenge" {
				http.Error(w, `{"error":"insufficient_scope"}`, http.StatusForbidden)
				return
			}

			if validClaims.ID != "" && isRevoked(validClaims.ID) {
				http.Error(w, `{"error":"token_revoked"}`, http.StatusUnauthorized)
				return
			}

			mapClaims := jwt.MapClaims{
				"user":  validClaims.User,
				"scope": validClaims.Scope,
				"jti":   validClaims.ID,
			}
			ctx := context.WithValue(r.Context(), auth.ClaimsContextKey, mapClaims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})

		if len(cfg.AllowedIPs) > 0 {
			return ipallow.New(cfg.AllowedIPs, s.logger, ipMgr)(authHandler)
		}
		return authHandler
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	state := s.apiShared.State()
	cfg := state.Global.Admin

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if s.keeperStore == nil || s.keeperStore.IsLocked() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]any{
			"status":       "challenge_required",
			"requirements": []string{"keeper_unlock"},
		})
		return
	}

	if !s.verifyAdminUser(creds.Username, creds.Password) {
		addJitter(10 * time.Millisecond)
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	var requirements []string
	if cfg.TOTP.Enabled.Active() {
		requirements = append(requirements, "totp")
	}

	w.Header().Set("Content-Type", "application/json")

	if len(requirements) > 0 {
		tokenString, _, err := s.generateAdminToken(creds.Username, string(challengeSecret), "challenge", challengeTokenTTL)
		if err != nil {
			s.logger.Error("Failed to sign challenge token", "err", err)
			http.Error(w, "Internal Signing Error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]any{
			"status":       "challenge_required",
			"token":        tokenString,
			"requirements": requirements,
		})
		return
	}

	jwtSecret, err := s.getAdminJWTSecret(creds.Username)
	if err != nil {
		s.logger.Error("Failed to get admin JWT secret from keeper", "err", err, "user", creds.Username)
		http.Error(w, "JWT secret not configured or inaccessible", http.StatusForbidden)
		return
	}

	tokenString, expirationTime, err := s.generateAdminToken(creds.Username, jwtSecret, "full", adminTokenTTL)
	if err != nil {
		s.logger.Error("Failed to sign admin token", "err", err)
		http.Error(w, "Internal Signing Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"token":   tokenString,
		"expires": expirationTime.Format(time.RFC3339),
	})
}

func (s *Server) handleLoginChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	state := s.apiShared.State()
	cfg := state.Global.Admin

	authHeader := r.Header.Get(woos.AuthorizationHeaderKey)
	if authHeader == "" {
		http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
		return
	}

	tokenStr := strings.TrimPrefix(authHeader, woos.HeaderKeyBearer+" ")

	token, err := jwt.ParseWithClaims(tokenStr, &adminClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return challengeSecret, nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "Invalid or expired challenge token", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(*adminClaims)
	if !ok || claims.Scope != "challenge" {
		http.Error(w, "Invalid token scope", http.StatusForbidden)
		return
	}

	var creds struct {
		TOTP             string `json:"totp"`
		KeeperPassphrase string `json:"keeper_passphrase"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if s.keeperStore != nil && s.keeperStore.IsLocked() {
		if creds.KeeperPassphrase == "" {
			addJitter(5 * time.Millisecond)
			http.Error(w, "Keeper passphrase required", http.StatusUnauthorized)
			return
		}
		pass := []byte(creds.KeeperPassphrase)
		unlockErr := s.keeperStore.Unlock(pass)
		zero.Bytes(pass)
		if unlockErr != nil {
			addJitter(10 * time.Millisecond)
			http.Error(w, "Invalid Keeper passphrase", http.StatusUnauthorized)
			return
		}
		secrets.NewResolver(s.keeperStore).Wire()
		s.logger.Info("keeper unlocked during admin challenge")

		go s.Reload()
	}

	if cfg.TOTP.Enabled.Active() {
		if creds.TOTP == "" {
			addJitter(5 * time.Millisecond)
			http.Error(w, "TOTP code required", http.StatusUnauthorized)
			return
		}
		if !s.totpHandler.VerifyCode(claims.User, creds.TOTP) {
			addJitter(5 * time.Millisecond)
			http.Error(w, "Invalid TOTP code", http.StatusUnauthorized)
			return
		}
	}

	jwtSecret, err := s.getAdminJWTSecret(claims.User)
	if err != nil {
		s.logger.Error("Failed to get admin JWT secret from keeper", "err", err, "user", claims.User)
		http.Error(w, "JWT secret not configured or inaccessible", http.StatusForbidden)
		return
	}

	tokenString, expirationTime, err := s.generateAdminToken(claims.User, jwtSecret, "full", adminTokenTTL)
	if err != nil {
		s.logger.Error("Failed to sign admin token", "err", err)
		http.Error(w, "Internal Signing Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"token":   tokenString,
		"expires": expirationTime.Format(time.RFC3339),
	})
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	claims, ok := auth.GetClaims(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	user, _ := claims["user"].(string)
	if user == "" {
		http.Error(w, "Invalid user claim", http.StatusUnauthorized)
		return
	}

	jwtSecret, err := s.getAdminJWTSecret(user)
	if err != nil {
		s.logger.Error("Failed to get admin JWT secret from keeper", "err", err, "user", user)
		http.Error(w, "JWT secret not configured or inaccessible", http.StatusForbidden)
		return
	}

	tokenString, expirationTime, err := s.generateAdminToken(user, jwtSecret, "full", adminTokenTTL)
	if err != nil {
		s.logger.Error("Failed to sign admin token", "err", err)
		http.Error(w, "Internal Signing Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token":   tokenString,
		"expires": expirationTime.Format(time.RFC3339),
	})
}

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

	parser := new(jwt.Parser)
	unverifiedToken, _, err := parser.ParseUnverified(tokenStr, &adminClaims{})
	if err != nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	claims, ok := unverifiedToken.Claims.(*adminClaims)
	if !ok || claims.User == "" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var secret []byte
	if claims.Scope == "challenge" {
		secret = challengeSecret
	} else {
		jwtSecret, err := s.getAdminJWTSecret(claims.User)
		if err != nil {
			w.WriteHeader(http.StatusOK)
			return
		}
		secret = []byte(jwtSecret)
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return secret, nil
	})

	if err != nil || !token.Valid {
		w.WriteHeader(http.StatusOK)
		return
	}

	if mapClaims, ok := token.Claims.(jwt.MapClaims); ok {
		if jti, _ := mapClaims["jti"].(string); jti != "" {
			exp := adminTokenTTL
			if expClaim, ok := mapClaims["exp"].(float64); ok {
				if remaining := time.Until(time.Unix(int64(expClaim), 0)); remaining > 0 {
					exp = remaining
				}
			}
			s.resource.TimeStore.SetTTL(jti, time.Now().Add(exp), exp)
			s.resource.Lifetime.ScheduleTimed(r.Context(), jti, func(ctx context.Context, id string) {
				s.resource.TimeStore.Delete(id)
			}, exp)
		}
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) generateAdminToken(username, secret, scope string, ttl time.Duration) (string, time.Time, error) {
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", time.Time{}, err
	}
	jti := hex.EncodeToString(jtiBytes)

	now := time.Now()
	expirationTime := now.Add(ttl)

	issuer := adminTokenIssuer
	if scope == "challenge" {
		issuer = challengeTokenIssuer
	}

	claims := &adminClaims{
		User:  username,
		Scope: scope,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    issuer,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	return tokenString, expirationTime, err
}

func (s *Server) verifyAdminUser(username, password string) bool {
	userKey := expect.Vault().AdminUser(username)
	data, err := s.keeperStore.Get(userKey)

	hashToCompare := dummyHash
	if err == nil && len(data) > 0 {
		var user alaye.AdminUser
		if jsonErr := json.Unmarshal(data, &user); jsonErr == nil && user.PasswordHash != "" {
			hashToCompare = []byte(user.PasswordHash)
		}
	}

	inputUserHash := sha256.Sum256([]byte(username))
	_ = inputUserHash

	found := int32(0)
	if err == nil && len(data) > 0 {
		found = 1
	}

	bcryptErr := bcrypt.CompareHashAndPassword(hashToCompare, []byte(password))
	return subtle.ConstantTimeEq(found, 1) == 1 && bcryptErr == nil
}

func (s *Server) verifyCredentials(users []string, username, password string) bool {
	inputUserHash := sha256.Sum256([]byte(username))
	foundHash := dummyHash
	found := 0

	for _, u := range users {
		parts := strings.SplitN(u, ":", 2)
		if len(parts) != 2 {
			continue
		}
		storedUserHash := sha256.Sum256([]byte(parts[0]))
		match := subtle.ConstantTimeCompare(inputUserHash[:], storedUserHash[:])
		if match == 1 {
			foundHash = []byte(parts[1])
			found = 1
		}
	}

	err := bcrypt.CompareHashAndPassword(foundHash, []byte(password))
	return subtle.ConstantTimeEq(int32(found), 1) == 1 && err == nil
}

func (s *Server) handleConfigDump(w http.ResponseWriter, r *http.Request) {
	format := detectFormat(r)
	hosts, _ := s.hostManager.LoadAll()

	if format == "hcl" {
		w.Header().Set("Content-Type", "application/hcl")
		http.Error(w, "HCL format for full config not yet implemented", http.StatusNotImplemented)
		return
	}

	state := s.apiShared.State()
	resp := struct {
		Global  any `json:"global"`
		Hosts   any `json:"hosts"`
		Cluster any `json:"cluster,omitempty"`
	}{
		Global: sanitizeGlobalConfig(state.Global),
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

func (s *Server) handleConfigGlobal(w http.ResponseWriter, r *http.Request) {
	format := detectFormat(r)
	if format == "hcl" {
		w.Header().Set("Content-Type", "application/hcl")
		http.Error(w, "HCL format not yet implemented", http.StatusNotImplemented)
		return
	}
	state := s.apiShared.State()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sanitizeGlobalConfig(state.Global))
}

func (s *Server) handleConfigHosts(w http.ResponseWriter, r *http.Request) {
	format := detectFormat(r)
	hosts, _ := s.hostManager.LoadAll()
	if format == "hcl" {
		http.Error(w, "HCL format for hosts list not supported", http.StatusNotAcceptable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sanitizeHostConfigs(hosts))
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	var logPath string
	state := s.apiShared.State()
	if state.Global.Logging.File.Enabled.Active() {
		logPath = state.Global.Logging.File.Path
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

func (s *Server) getAdminJWTSecret(username string) (string, error) {
	if s.keeperStore == nil || s.keeperStore.IsLocked() {
		return "", errors.New("keeper is locked or unavailable")
	}
	key := expect.Vault().AdminJWT(username)
	secretBytes, err := s.keeperStore.Get(key)
	if err != nil {
		p := security.NewPassword()
		secret, _ := p.Generate(woos.JWTSecretLength)
		if setErr := s.keeperStore.Set(key, []byte(secret)); setErr == nil {
			return secret, nil
		}
		return "", fmt.Errorf("could not retrieve secret for key %s: %w", key, err)
	}
	return string(secretBytes), nil
}

func addJitter(maxDelay time.Duration) {
	jitter := time.Duration(mtrand.Int63n(int64(maxDelay)))
	time.Sleep(jitter)
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
