package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/hub/discovery"
	"github.com/agberohq/agbero/internal/pkg/parser"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/agberohq/keeper"
	"github.com/go-chi/chi/v5"
	"github.com/olekukonko/ll"
)

// AuthHandler registers the route-auth management API.
//
// The API edits two existing HCL blocks in place — basic_auth and protect —
// and stores new password hashes in Keeper. HCL is the source of truth for
// membership; Keeper is the source of truth for the hash. That split keeps
// credentials out of config files while leaving comments and hand-edited
// settings intact.
func AuthHandler(s *Shared, r chi.Router) {
	a := NewAuth(s)
	r.Route("/auth", func(r chi.Router) {
		r.Get("/{domain}", a.get)
		r.Put("/{domain}/config", a.updateConfig)
		r.Post("/{domain}/users", a.addUser)
		r.Put("/{domain}/users", a.resetUser)
		r.Delete("/{domain}/users", a.deleteUser)
	})
}

// authSecretBroadcaster mirrors the Keeper API's optional cluster fan-out.
// Without it a user added through the admin UI would only be able to log in on
// the node that handled the request.
type authSecretBroadcaster interface {
	BroadcastSecret(key string, plaintext []byte) error
}

// Auth serves route-level Basic/Protect auth management for a host.
type Auth struct {
	discovery *discovery.Host
	hostsDir  expect.Folder
	store     *keeper.Keeper
	cluster   authSecretBroadcaster
	logger    *ll.Logger
	password  *security.Password

	// mu serialises the read-modify-write cycle on HCL files. The admin UI is
	// single-operator by design, but two browser tabs must not lose an update.
	mu sync.Mutex
}

// NewAuth constructs an Auth handler from shared application state.
func NewAuth(cfg *Shared) *Auth {
	var hostsDir expect.Folder
	if state := cfg.State(); state.Global != nil {
		hostsDir = state.Global.Storage.HostsDir
	}
	a := &Auth{
		discovery: cfg.Discovery,
		hostsDir:  hostsDir,
		store:     cfg.Keeper,
		logger:    cfg.Logger.Namespace("api/auth"),
		password:  security.NewPassword(),
	}
	// Avoid assigning a nil *cluster.Manager to the interface (non-nil
	// interface wrapping a nil pointer).
	if cfg.Cluster != nil {
		a.cluster = cfg.Cluster
	}
	return a
}

var (
	errAuthHostNotFound  = errors.New("host not found")
	errAuthRouteNotFound = errors.New("route not found")
	errAuthUserExists    = errors.New("user already exists")
	errAuthUserNotFound  = errors.New("user not found")
	errAuthKeeperMissing = errors.New("keeper is not configured")
	errAuthKeeperLocked  = errors.New("keeper is locked")
)

// authUserView never carries a hash or password. Inline entries are reported as
// source "inline" with no value; Keeper entries expose only the reference path.
type authUserView struct {
	Username  string `json:"username"`
	Source    string `json:"source"`
	Ref       string `json:"ref,omitempty"`
	KeeperKey string `json:"keeper_key,omitempty"`
}

type authBasicView struct {
	Enabled bool           `json:"enabled"`
	Realm   string         `json:"realm"`
	Users   []authUserView `json:"users"`
}

type authProtectView struct {
	Enabled    bool           `json:"enabled"`
	Title      string         `json:"title"`
	Users      []authUserView `json:"users"`
	SessionTTL string         `json:"session_ttl"`
	CookieName string         `json:"cookie_name"`
}

type authRouteView struct {
	Path      string          `json:"path"`
	Protocol  string          `json:"protocol,omitempty"`
	BasicAuth authBasicView   `json:"basic_auth"`
	Protect   authProtectView `json:"protect"`
}

type authHostView struct {
	Host   string          `json:"host"`
	Routes []authRouteView `json:"routes"`
}

type authUserRequest struct {
	Route    string `json:"route"`
	Mode     string `json:"mode"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type authConfigBody struct {
	Route      string  `json:"route"`
	Mode       string  `json:"mode"`
	Enabled    *bool   `json:"enabled"`
	Realm      *string `json:"realm"`
	Title      *string `json:"title"`
	SessionTTL *string `json:"session_ttl"`
	CookieName *string `json:"cookie_name"`
}

func (a *Auth) get(w http.ResponseWriter, r *http.Request) {
	domain, cfg, ok := a.lookupHost(w, r)
	if !ok {
		return
	}

	view := authHostView{Host: domain, Routes: make([]authRouteView, 0, len(cfg.Routes))}
	for i := range cfg.Routes {
		route := &cfg.Routes[i]
		view.Routes = append(view.Routes, authRouteView{
			Path:     route.Path,
			Protocol: route.Protocol,
			BasicAuth: authBasicView{
				Enabled: route.BasicAuth.Enabled.Active(),
				Realm:   route.BasicAuth.Realm,
				Users:   authUsersView(route.BasicAuth.Users),
			},
			Protect: authProtectView{
				Enabled:    route.Protect.Enabled.Active(),
				Title:      route.Protect.Title,
				Users:      authUsersView(route.Protect.Users),
				SessionTTL: route.Protect.SessionTTL.String(),
				CookieName: route.Protect.CookieName,
			},
		})
	}
	a.jsonResponse(w, http.StatusOK, view)
}

func (a *Auth) updateConfig(w http.ResponseWriter, r *http.Request) {
	domain, cfg, ok := a.lookupHost(w, r)
	if !ok {
		return
	}

	var body authConfigBody
	if !decodeAuthJSON(w, r, &body) {
		return
	}
	routePath, mode, ok := a.requestRouteAndMode(w, r, body.Route, body.Mode)
	if !ok {
		return
	}
	if body.Enabled == nil && body.Realm == nil && body.Title == nil &&
		body.SessionTTL == nil && body.CookieName == nil {
		a.errorResponse(w, http.StatusBadRequest, "no configuration fields supplied")
		return
	}
	if routeByPath(cfg, routePath) == nil {
		a.errorResponse(w, http.StatusNotFound, errAuthRouteNotFound.Error())
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	fileCfg, _, raw, err := a.mutationContext(domain)
	if err != nil {
		a.writeMutationError(w, err)
		return
	}
	if routeByPath(fileCfg, routePath) == nil {
		a.errorResponse(w, http.StatusNotFound, errAuthRouteNotFound.Error())
		return
	}

	mutated, err := mutateAuthSettings(raw, routePath, mode, authConfigRequest{
		Enabled:    body.Enabled,
		Realm:      body.Realm,
		Title:      body.Title,
		SessionTTL: body.SessionTTL,
		CookieName: body.CookieName,
	})
	if err != nil {
		a.errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := a.applyHCL(domain, mutated); err != nil {
		a.writeMutationError(w, err)
		return
	}

	a.jsonResponse(w, http.StatusOK, map[string]any{
		"status": "ok",
		"host":   domain,
		"route":  routePath,
		"mode":   string(mode),
	})
}

func (a *Auth) addUser(w http.ResponseWriter, r *http.Request) {
	domain, _, ok := a.lookupHost(w, r)
	if !ok {
		return
	}
	req, routePath, mode, ok := a.decodeUserRequest(w, r)
	if !ok {
		return
	}

	hash, err := a.password.Hash(req.Password)
	if err != nil {
		a.errorResponse(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if _, err := a.requireKeeper(); err != nil {
		a.writeMutationError(w, err)
		return
	}

	fileCfg, _, raw, err := a.mutationContext(domain)
	if err != nil {
		a.writeMutationError(w, err)
		return
	}
	route := routeByPath(fileCfg, routePath)
	if route == nil {
		a.errorResponse(w, http.StatusNotFound, errAuthRouteNotFound.Error())
		return
	}
	entries := authEntries(route, mode)
	if authUserIndex(entries, req.Username) >= 0 {
		a.errorResponse(w, http.StatusConflict, errAuthUserExists.Error())
		return
	}

	key := keeperKeyFor(domain, routePath, mode, req.Username)
	if _, exists, err := a.getSecret(key); err != nil {
		a.writeMutationError(w, err)
		return
	} else if exists {
		a.errorResponse(w, http.StatusConflict, "a Keeper secret already exists for this user")
		return
	}

	if err := a.setSecret(key, hash); err != nil {
		a.writeMutationError(w, err)
		return
	}

	newEntries := append(append([]string(nil), entries...), req.Username+":ss://"+key)
	mutated, err := mutateAuthUsers(raw, routePath, mode, newEntries)
	if err == nil {
		_, err = a.applyHCL(domain, mutated)
	}
	if err != nil {
		// Do not leave an orphan secret behind when the HCL write fails.
		_ = a.deleteSecret(key)
		a.writeMutationError(w, err)
		return
	}

	a.jsonResponse(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"host":       domain,
		"route":      routePath,
		"mode":       string(mode),
		"username":   req.Username,
		"source":     "keeper",
		"ref":        "ss://" + key,
		"keeper_key": key,
		"created":    true,
	})
}

func (a *Auth) resetUser(w http.ResponseWriter, r *http.Request) {
	domain, _, ok := a.lookupHost(w, r)
	if !ok {
		return
	}
	req, routePath, mode, ok := a.decodeUserRequest(w, r)
	if !ok {
		return
	}

	hash, err := a.password.Hash(req.Password)
	if err != nil {
		a.errorResponse(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if _, err := a.requireKeeper(); err != nil {
		a.writeMutationError(w, err)
		return
	}

	fileCfg, _, raw, err := a.mutationContext(domain)
	if err != nil {
		a.writeMutationError(w, err)
		return
	}
	route := routeByPath(fileCfg, routePath)
	if route == nil {
		a.errorResponse(w, http.StatusNotFound, errAuthRouteNotFound.Error())
		return
	}
	entries := authEntries(route, mode)
	idx := authUserIndex(entries, req.Username)
	if idx < 0 {
		a.errorResponse(w, http.StatusNotFound, errAuthUserNotFound.Error())
		return
	}

	_, oldSecret, _ := parseAuthUserEntry(entries[idx])
	key := secretRefKey(oldSecret)
	if key == "" {
		key = keeperKeyFor(domain, routePath, mode, req.Username)
	}

	oldValue, existed, err := a.getSecret(key)
	if err != nil {
		a.writeMutationError(w, err)
		return
	}
	if err := a.setSecret(key, hash); err != nil {
		a.writeMutationError(w, err)
		return
	}

	newEntries := append([]string(nil), entries...)
	newEntries[idx] = req.Username + ":ss://" + key
	mutated, err := mutateAuthUsers(raw, routePath, mode, newEntries)
	if err == nil {
		_, err = a.applyHCL(domain, mutated)
	}
	if err != nil {
		a.rollbackSecret(key, oldValue, existed)
		a.writeMutationError(w, err)
		return
	}

	a.jsonResponse(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"host":       domain,
		"route":      routePath,
		"mode":       string(mode),
		"username":   req.Username,
		"source":     "keeper",
		"ref":        "ss://" + key,
		"keeper_key": key,
	})
}

func (a *Auth) deleteUser(w http.ResponseWriter, r *http.Request) {
	domain, _, ok := a.lookupHost(w, r)
	if !ok {
		return
	}
	routePath, mode, ok := a.requestRouteAndMode(w, r, r.URL.Query().Get("route"), r.URL.Query().Get("mode"))
	if !ok {
		return
	}
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if !validAuthUsername(username) {
		a.errorResponse(w, http.StatusBadRequest, "username is required and must be a plain username")
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	fileCfg, _, raw, err := a.mutationContext(domain)
	if err != nil {
		a.writeMutationError(w, err)
		return
	}
	route := routeByPath(fileCfg, routePath)
	if route == nil {
		a.errorResponse(w, http.StatusNotFound, errAuthRouteNotFound.Error())
		return
	}
	entries := authEntries(route, mode)
	idx := authUserIndex(entries, username)
	if idx < 0 {
		a.errorResponse(w, http.StatusNotFound, errAuthUserNotFound.Error())
		return
	}

	_, oldSecret, _ := parseAuthUserEntry(entries[idx])
	key := secretRefKey(oldSecret)
	if key != "" {
		if _, err = a.requireKeeper(); err != nil {
			a.writeMutationError(w, err)
			return
		}
	}

	newEntries := make([]string, 0, len(entries)-1)
	newEntries = append(newEntries, entries[:idx]...)
	newEntries = append(newEntries, entries[idx+1:]...)

	mutated, err := mutateAuthUsers(raw, routePath, mode, newEntries)
	if err == nil {
		_, err = a.applyHCL(domain, mutated)
	}
	if err != nil {
		a.writeMutationError(w, err)
		return
	}

	if key != "" {
		if err := a.deleteSecret(key); err != nil {
			// The HCL no longer references the secret, so this is an orphan,
			// not a broken login. Report it without failing the operation.
			a.logger.Fields("key", key, "err", err).Warn("auth: user removed from HCL but Keeper delete failed")
		}
	}

	a.jsonResponse(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"host":     domain,
		"route":    routePath,
		"mode":     string(mode),
		"username": username,
		"deleted":  true,
	})
}

func (a *Auth) lookupHost(w http.ResponseWriter, r *http.Request) (string, *alaye.Host, bool) {
	domain, err := normalizeHostDomain(chi.URLParam(r, "domain"))
	if err != nil {
		a.errorResponse(w, http.StatusBadRequest, err.Error())
		return "", nil, false
	}
	cfg := a.discovery.Get(domain)
	if cfg == nil {
		a.errorResponse(w, http.StatusNotFound, errAuthHostNotFound.Error())
		return "", nil, false
	}
	return domain, cfg, true
}

func (a *Auth) decodeUserRequest(w http.ResponseWriter, r *http.Request) (authUserRequest, string, authMode, bool) {
	var req authUserRequest
	if !decodeAuthJSON(w, r, &req) {
		return req, "", "", false
	}
	req.Username = strings.TrimSpace(req.Username)
	if !validAuthUsername(req.Username) {
		a.errorResponse(w, http.StatusBadRequest, "username is required and must contain only letters, numbers, dots, dashes, underscores, or @")
		return req, "", "", false
	}
	if req.Password == "" {
		a.errorResponse(w, http.StatusBadRequest, "password is required")
		return req, "", "", false
	}
	if len(req.Password) > 72 {
		// bcrypt silently truncates beyond 72 bytes; reject instead of creating
		// a credential whose tail does not actually participate in the hash.
		a.errorResponse(w, http.StatusBadRequest, "password must be 72 bytes or fewer")
		return req, "", "", false
	}

	routePath, mode, ok := a.requestRouteAndMode(w, r, req.Route, req.Mode)
	if !ok {
		return req, "", "", false
	}
	if mode == authModeProtect && strings.Contains(routePath, "*") {
		a.errorResponse(w, http.StatusBadRequest, "protect requires a concrete route path (wildcards are not supported)")
		return req, "", "", false
	}
	return req, routePath, mode, true
}

func (a *Auth) requestRouteAndMode(w http.ResponseWriter, r *http.Request, rawRoute, rawMode string) (string, authMode, bool) {
	rawRoute = firstNonEmpty(rawRoute, r.URL.Query().Get("route"))
	rawMode = firstNonEmpty(rawMode, r.URL.Query().Get("mode"))

	routePath, err := authRoutePath(rawRoute)
	if err != nil {
		a.errorResponse(w, http.StatusBadRequest, err.Error())
		return "", "", false
	}
	mode, err := parseAuthMode(rawMode)
	if err != nil {
		a.errorResponse(w, http.StatusBadRequest, err.Error())
		return "", "", false
	}
	return routePath, mode, true
}

// mutationContext parses the current file so user membership is read from disk,
// not from a possibly stale in-memory copy.
func (a *Auth) mutationContext(domain string) (*alaye.Host, string, []byte, error) {
	cfg := a.discovery.Get(domain)
	if cfg == nil {
		return nil, "", nil, errAuthHostNotFound
	}
	sourceFile := cfg.SourceFile
	if sourceFile == "" {
		sourceFile = zulu.NormalizeHost(domain) + def.HCLSuffix
	}
	path, err := safeHostSourcePath(a.hostsDir.Path(), sourceFile)
	if err != nil {
		return nil, "", nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", nil, fmt.Errorf("read host config: %w", err)
	}
	fileCfg, err := parseHostBytes(raw)
	if err != nil {
		return nil, sourceFile, raw, err
	}
	return fileCfg, sourceFile, raw, nil
}

// applyHCL validates the mutated document, writes it atomically through
// discovery (which uses os.Root + rename), then publishes the new config.
func (a *Auth) applyHCL(domain string, raw []byte) (*alaye.Host, error) {
	cfg, err := parseHostBytes(raw)
	if err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	existing := a.discovery.Get(domain)
	if existing == nil {
		return nil, errAuthHostNotFound
	}
	if existing.SourceFile != "" {
		cfg.SourceFile = existing.SourceFile
	}
	if err := a.discovery.CreateRaw(domain, cfg, raw); err != nil {
		return nil, fmt.Errorf("save host config: %w", err)
	}
	a.discovery.Set(domain, cfg)
	return cfg, nil
}

func parseHostBytes(raw []byte) (*alaye.Host, error) {
	tmp, err := os.CreateTemp("", "protect_*.hcl")
	if err != nil {
		return nil, fmt.Errorf("create temp config: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("write temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("write temp config: %w", err)
	}

	cfg, err := parser.ParseHostConfig(name)
	if err != nil {
		return nil, fmt.Errorf("parse host config: %w", err)
	}
	woos.DefaultHost(cfg)
	return cfg, nil
}

func safeHostSourcePath(base, name string) (string, error) {
	if name == "" || strings.ContainsRune(name, 0) || strings.Contains(name, `\`) {
		return "", fmt.Errorf("invalid host config filename %q", name)
	}
	clean := filepath.Clean(name)
	if filepath.IsAbs(clean) || clean == "." || clean == ".." ||
		strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("host config filename %q escapes the hosts directory", name)
	}
	if !strings.HasSuffix(strings.ToLower(clean), def.HCLSuffix) {
		return "", fmt.Errorf("host config filename %q must end in %q", name, def.HCLSuffix)
	}
	return filepath.Join(base, clean), nil
}

func (a *Auth) requireKeeper() (*keeper.Keeper, error) {
	if a.store == nil {
		return nil, errAuthKeeperMissing
	}
	if a.store.IsLocked() {
		return nil, errAuthKeeperLocked
	}
	return a.store, nil
}

func (a *Auth) getSecret(key string) ([]byte, bool, error) {
	store, err := a.requireKeeper()
	if err != nil {
		return nil, false, err
	}
	value, err := store.Get(key)
	if err != nil {
		if errors.Is(err, keeper.ErrKeyNotFound) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return value, true, nil
}

func (a *Auth) setSecret(key, value string) error {
	store, err := a.requireKeeper()
	if err != nil {
		return err
	}
	if err := store.EnsureBucket(key); err != nil {
		return fmt.Errorf("prepare Keeper namespace: %w", err)
	}
	if err := store.SetString(key, value); err != nil {
		return fmt.Errorf("write Keeper secret: %w", err)
	}
	if a.cluster != nil {
		if err := a.cluster.BroadcastSecret(key, []byte(value)); err != nil {
			a.logger.Fields("key", key, "err", err).Warn("auth: secret written locally but cluster broadcast failed")
		}
	}
	return nil
}

func (a *Auth) deleteSecret(key string) error {
	store, err := a.requireKeeper()
	if err != nil {
		return err
	}
	if err := store.Delete(key); err != nil && !errors.Is(err, keeper.ErrKeyNotFound) {
		return err
	}
	if a.cluster != nil {
		if err := a.cluster.BroadcastSecret(key, nil); err != nil {
			a.logger.Fields("key", key, "err", err).Warn("auth: secret deleted locally but cluster broadcast failed")
		}
	}
	return nil
}

func (a *Auth) rollbackSecret(key string, oldValue []byte, existed bool) {
	if existed {
		_ = a.setSecret(key, string(oldValue))
		return
	}
	_ = a.deleteSecret(key)
}

func (a *Auth) writeMutationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errAuthKeeperMissing):
		a.errorResponse(w, http.StatusServiceUnavailable, err.Error())
	case errors.Is(err, errAuthKeeperLocked):
		a.errorResponse(w, http.StatusLocked, err.Error())
	case errors.Is(err, errAuthHostNotFound), errors.Is(err, errAuthRouteNotFound), errors.Is(err, errAuthUserNotFound):
		a.errorResponse(w, http.StatusNotFound, err.Error())
	case errors.Is(err, errAuthUserExists):
		a.errorResponse(w, http.StatusConflict, err.Error())
	default:
		a.errorResponse(w, http.StatusBadRequest, err.Error())
	}
}

func (a *Auth) jsonResponse(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if data != nil {
		if err := json.NewEncoder(w).Encode(data); err != nil {
			a.logger.Error("failed to encode response", "err", err)
		}
	}
}

func (a *Auth) errorResponse(w http.ResponseWriter, code int, msg string) {
	a.jsonResponse(w, code, map[string]string{"error": msg})
}

func decodeAuthJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON payload"})
		return false
	}
	return true
}

func authRoutePath(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("route is required")
	}
	if !strings.HasPrefix(raw, "/") {
		return "", fmt.Errorf("route must start with '/'")
	}
	if strings.ContainsAny(raw, "\r\n\t\\") {
		return "", fmt.Errorf("route contains invalid characters")
	}
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.IsAbs() || u.Host != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("route must be an absolute path without query or fragment")
	}
	return raw, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func routeByPath(cfg *alaye.Host, routePath string) *alaye.Route {
	if cfg == nil {
		return nil
	}
	for i := range cfg.Routes {
		if cfg.Routes[i].Path == routePath {
			return &cfg.Routes[i]
		}
	}
	return nil
}

func authEntries(route *alaye.Route, mode authMode) []string {
	if route == nil {
		return nil
	}
	if mode == authModeProtect {
		return route.Protect.Users
	}
	return route.BasicAuth.Users
}

func authUsersView(entries []string) []authUserView {
	out := make([]authUserView, 0, len(entries))
	for _, entry := range entries {
		username, secret, ok := parseAuthUserEntry(entry)
		if !ok {
			out = append(out, authUserView{Username: username, Source: "invalid"})
			continue
		}
		if expect.Value(secret).IsSecretStoreRef() {
			out = append(out, authUserView{
				Username:  username,
				Source:    "keeper",
				Ref:       secret,
				KeeperKey: secretRefKey(secret),
			})
			continue
		}
		out = append(out, authUserView{Username: username, Source: "inline"})
	}
	return out
}

func parseAuthUserEntry(entry string) (username, secret string, ok bool) {
	username, secret, ok = strings.Cut(strings.TrimSpace(entry), ":")
	username = strings.TrimSpace(username)
	secret = strings.TrimSpace(secret)
	return username, secret, ok && username != "" && secret != ""
}

func authUserIndex(entries []string, username string) int {
	for i, entry := range entries {
		u, _, ok := parseAuthUserEntry(entry)
		if ok && u == username {
			return i
		}
	}
	return -1
}

// secretRefKey maps a secret reference to the default-scheme key Keeper stores.
// Only the ss:// family is manageable here; other explicit schemes (vault://,
// keeper://) address a different scheme bucket, so callers treat them as
// non-managed references rather than rewriting them to a different bucket.
func secretRefKey(ref string) string {
	ref = strings.TrimSpace(ref)
	for _, prefix := range []string{"ss://", "ss.", "keeper."} {
		if after, ok := strings.CutPrefix(ref, prefix); ok {
			return after
		}
	}
	return ""
}

var authUsernameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$`)

func validAuthUsername(username string) bool {
	return authUsernameRe.MatchString(strings.TrimSpace(username))
}

// keeperKeyFor derives a stable, human-readable key that also satisfies
// expect.Secret's namespace/key/subkey grammar. Segments that need rewriting get
// a short hash suffix so two distinct values can never collapse onto one key.
func keeperKeyFor(domain, routePath string, mode authMode, username string) string {
	domainSeg := keySegment(domain, 96, true)
	routeSeg := keySegment(strings.Trim(routePath, "/"), 48, false)
	if routeSeg == "" {
		routeSeg = "root"
	}
	userSeg := keySegment(username, 48, false)
	return "auth/" + domainSeg + "/" + routeSeg + "/" + string(mode) + "/" + userSeg
}

func keySegment(value string, maxLen int, allowDot bool) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "root"
	}
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		case r == '.' && allowDot:
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	seg := strings.Trim(b.String(), "_-")
	if seg == "" || seg == ".." {
		seg = "root"
	}
	if seg != value {
		sum := sha256.Sum256([]byte(value))
		seg += "-" + hex.EncodeToString(sum[:4])
	}
	if len(seg) > maxLen {
		sum := sha256.Sum256([]byte(seg))
		seg = seg[:maxLen-9] + "-" + hex.EncodeToString(sum[:4])
	}
	return seg
}
