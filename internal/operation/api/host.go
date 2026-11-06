package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/hub/discovery"
	"github.com/agberohq/agbero/internal/hub/tlss"
	"github.com/agberohq/agbero/internal/pkg/parser"
	"github.com/go-chi/chi/v5"
	"github.com/olekukonko/ll"
)

// HostHandler registers all host management API endpoints under the /discovery prefix on the provided chi.Router.
// Caller should apply authentication middleware via r.Use() before or within the route group.
func HostHandler(s *Shared, r chi.Router) {
	h := NewHost(s)

	r.Route("/discovery", func(r chi.Router) {
		r.Get("/", h.list)
		r.Post("/", h.create)
		r.Post("/preview", h.preview)
		r.With(ValidateDomainParam).Get("/{domain}", h.get)
		// HEAD is used by the admin UI to probe for an existing host; net/http
		// discards the body, so the GET handler is the right implementation.
		r.With(ValidateDomainParam).Head("/{domain}", h.get)
		r.With(ValidateDomainParam).Put("/{domain}", h.update)
		r.With(ValidateDomainParam).Delete("/{domain}", h.delete)
	})
}

// Host provides HTTP handlers for host configuration CRUD operations with HCL/JSON support.
// It encapsulates the discovery host ppk, storage directory, and logger for host operations.
type Host struct {
	discovery *discovery.Host
	hostsDir  expect.Folder
	logger    *ll.Logger
	tls       *tlss.Manager
}

// NewHost initializes a Host instance with shared application dependencies.
// It configures the logger namespace and prepares the handler for host management.
func NewHost(cfg *Shared) *Host {
	return &Host{
		discovery: cfg.Discovery,
		hostsDir:  cfg.State().Global.Storage.HostsDir,
		logger:    cfg.Logger.Namespace("api"),
		tls:       cfg.State().TLSS,
	}
}

// hostCreateRequest defines the JSON payload structure for creating a new host configuration.
type hostCreateRequest struct {
	Domain string      `json:"domain"`
	Config *alaye.Host `json:"config"`
}

// Validate performs validation on the host create request.
func (r hostCreateRequest) Validate() error {

	if r.Domain != "" {
		if _, err := normalizeHostDomain(r.Domain); err != nil {
			return fmt.Errorf("invalid domain: %w", err)
		}
	}

	if r.Config == nil {
		return fmt.Errorf("config is required")
	}

	// Validate routes for duplicates
	seenRoutes := make(map[string]bool)
	for _, route := range r.Config.Routes {
		path := route.Path
		if path == "" {
			path = "/"
		}
		if seenRoutes[path] {
			return fmt.Errorf("overlapping route detected: duplicate path %q", path)
		}
		seenRoutes[path] = true
	}

	seenProxies := make(map[string]bool)
	for _, proxy := range r.Config.Proxies {
		key := proxy.Listen + "|" + proxy.SNI
		if seenProxies[key] {
			return fmt.Errorf("overlapping TCP proxy detected: duplicate listen/SNI %q", key)
		}
		seenProxies[key] = true
	}

	if err := r.Config.Validate(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	return nil
}

// mergeRedactedSecrets copies credential fields that the read API replaced with
// def.RedactedValue (or dropped entirely, like basic_auth.users) from the
// existing config into the incoming one.
//
// Without this, the natural client flow — GET a host, edit it, PUT it back —
// writes "***" over every secret the sanitizer hid and silently destroys the
// host's credentials. Route matching is by path; if the route is new, nothing is
// merged. Must run BEFORE Validate(), because an empty basic_auth.users list is
// rejected when the block is enabled.
func mergeRedactedSecrets(existing, incoming *alaye.Host) {
	if existing == nil || incoming == nil {
		return
	}
	for i := range incoming.Routes {
		in := &incoming.Routes[i]
		ex := findRoute(existing.Routes, in.Path, i)
		if ex == nil {
			continue
		}

		if len(in.BasicAuth.Users) == 0 && len(ex.BasicAuth.Users) > 0 {
			in.BasicAuth.Users = append([]string(nil), ex.BasicAuth.Users...)
		}
		if in.JWTAuth.Secret == def.RedactedValue {
			in.JWTAuth.Secret = ex.JWTAuth.Secret
		}
		if in.OAuth.ClientSecret == def.RedactedValue {
			in.OAuth.ClientSecret = ex.OAuth.ClientSecret
		}
		if in.OAuth.CookieSecret == def.RedactedValue {
			in.OAuth.CookieSecret = ex.OAuth.CookieSecret
		}
		if in.ForwardAuth.URL == def.RedactedValue {
			in.ForwardAuth.URL = ex.ForwardAuth.URL
		}
		if in.ForwardAuth.TLS.ClientCert == def.RedactedValue {
			in.ForwardAuth.TLS.ClientCert = ex.ForwardAuth.TLS.ClientCert
		}
		if in.ForwardAuth.TLS.ClientKey == def.RedactedValue {
			in.ForwardAuth.TLS.ClientKey = ex.ForwardAuth.TLS.ClientKey
		}
		if isRedactedMap(in.Wasm.Config) {
			in.Wasm.Config = cloneStringMap(ex.Wasm.Config)
		}
		if in.Backends.Tunnel == def.RedactedValue {
			in.Backends.Tunnel = ex.Backends.Tunnel
		}
		mergeGitSecrets(&in.Web.Git, &ex.Web.Git)
		mergeGitSecrets(&in.Serverless.Git, &ex.Serverless.Git)
	}
}

// findRoute locates the existing route for an incoming one: by path first, then
// by position when the path is unknown (renamed route).
func findRoute(routes []alaye.Route, path string, idx int) *alaye.Route {
	for i := range routes {
		if routes[i].Path == path {
			return &routes[i]
		}
	}
	if idx >= 0 && idx < len(routes) {
		return &routes[idx]
	}
	return nil
}

func isRedactedMap(m map[string]string) bool {
	if len(m) != 1 {
		return false
	}
	v, ok := m[def.RedactedValue]
	return ok && v == def.RedactedValue
}

func cloneStringMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func mergeGitSecrets(in, ex *alaye.Git) {
	if in == nil || ex == nil {
		return
	}
	if in.Secret == def.RedactedValue {
		in.Secret = ex.Secret
	}
	if in.Auth.Password == def.RedactedValue {
		in.Auth.Password = ex.Auth.Password
	}
	if in.Auth.SSHKey == def.RedactedValue {
		in.Auth.SSHKey = ex.Auth.SSHKey
	}
	if in.Auth.SSHKeyPassphrase == def.RedactedValue {
		in.Auth.SSHKeyPassphrase = ex.Auth.SSHKeyPassphrase
	}
}

// hostNameRe matches the hostnames agbero accepts as a {domain} path parameter:
// optional wildcard label, dot-separated labels, optional trailing wildcard.
// It deliberately does NOT reuse expect.Raw.Domain(), which only recognises
// 2-label names whose TLD is in a small hard-coded public list — that rejected
// internal zones ("app.corp", "svc.internal") which create() accepts, leaving
// such hosts impossible to update or delete through the API (and the admin UI).
var hostNameRe = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`)

// normalizeHostDomain lower-cases and validates a {domain} path/query parameter.
func normalizeHostDomain(raw string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(raw))
	if err := validateDomainForStorage(d); err != nil {
		return "", err
	}
	if d != "localhost" && !hostNameRe.MatchString(d) {
		return "", fmt.Errorf("invalid domain format: %q", raw)
	}
	return d, nil
}

// validateDomainForStorage rejects domain values that must never reach the
// filesystem or the in-memory host index. Domains are used as filename
// components (hosts.d/<domain>.hcl), so separators and parent references are
// rejected here as well as in discovery.sanitizeHostFilename — the API must
// answer 400 instead of letting the write fail with 500.
func validateDomainForStorage(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain is required")
	}
	if strings.ContainsAny(domain, `/\`) || strings.Contains(domain, "..") {
		return fmt.Errorf("invalid domain %q: must not contain path separators or \"..\"", domain)
	}
	return nil
}

type hostUpdateRequest struct {
	Config *alaye.Host `json:"config"`
}

// Validate performs validation on the host update request.
func (r hostUpdateRequest) Validate() error {

	if r.Config == nil {
		return fmt.Errorf("config is required")
	}

	seenRoutes := make(map[string]bool)
	for _, route := range r.Config.Routes {
		path := route.Path
		if path == "" {
			path = "/"
		}
		if seenRoutes[path] {
			return fmt.Errorf("overlapping route detected: duplicate path %q", path)
		}
		seenRoutes[path] = true
	}

	// Validate proxies for duplicates
	seenProxies := make(map[string]bool)
	for _, proxy := range r.Config.Proxies {
		key := proxy.Listen + "|" + proxy.SNI
		if seenProxies[key] {
			return fmt.Errorf("overlapping TCP proxy detected: duplicate listen/SNI %q", key)
		}
		seenProxies[key] = true
	}

	if err := r.Config.Validate(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	return nil
}

// list handles GET requests to retrieve all registered host configurations as JSON.
// It loads discovery from discovery and sanitizes sensitive fields before response.
func (h *Host) list(w http.ResponseWriter, r *http.Request) {
	hosts, _ := h.discovery.LoadCanonicalByDomain()
	format := detectFormat(r)

	if format == "hcl" {
		http.Error(w, "HCL format not supported for host list, use ?format=json or request specific host", http.StatusNotAcceptable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sanitizeHostConfigs(hosts))
}

// get handles GET requests to retrieve a specific host configuration by domain.
// It supports both JSON and HCL output formats based on query parameter or Accept header.
func (h *Host) get(w http.ResponseWriter, r *http.Request) {
	domain := chi.URLParam(r, "domain")
	if domain == "" {
		http.Error(w, "Domain path parameter required", http.StatusBadRequest)
		return
	}
	domain = strings.ToLower(strings.TrimSpace(domain))

	validDomain, err := normalizeHostDomain(domain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	domain = validDomain

	existingCfg := h.discovery.Get(domain)
	if existingCfg == nil {
		http.Error(w, "Discovery not found", http.StatusNotFound)
		return
	}

	if detectFormat(r) == "hcl" {
		filename := existingCfg.SourceFile
		if filename == "" {
			filename = zulu.NormalizeHost(domain) + def.HCLSuffix
		}

		hclData, err := os.ReadFile(h.hostsDir.FilePath(filename))
		if err != nil {
			http.Error(w, "Failed to read HCL file", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/hcl")
		w.Write(hclData)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sanitizeHostConfigs(map[string]*alaye.Host{domain: existingCfg})[domain])
}

// writeBodyReadError maps a body read failure onto the right status code so a
// payload that exceeded def.HostConfigMaxBytes is reported as 413, not a generic 400.
func writeBodyReadError(w http.ResponseWriter, err error) {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
		return
	}
	http.Error(w, "Failed to read body", http.StatusBadRequest)
}

// readHostConfigBody reads the (already size-capped) request body once and
// reports whether it should be decoded as JSON.
//
// An explicit Content-Type decides. When the header is absent — oja's raw mode
// used to strip it, and plenty of HTTP clients omit it — the first non-space byte
// decides: '{' or '[' means JSON, anything else is HCL. Treating a missing header
// as JSON is what made an HCL upload answer "Invalid JSON payload".
func readHostConfigBody(w http.ResponseWriter, r *http.Request) (body []byte, isJSON, ok bool) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeBodyReadError(w, err)
		return nil, false, false
	}

	ct := strings.ToLower(r.Header.Get("Content-Type"))
	switch {
	case strings.Contains(ct, "json"):
		return body, true, true
	case strings.Contains(ct, "hcl"), strings.Contains(ct, "text/plain"):
		return body, false, true
	}

	if trimmed := bytes.TrimLeft(body, " \t\r\n"); len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		return body, true, true
	}
	return body, false, true
}

// create handles POST requests to register a new host configuration via JSON payload.
func (h *Host) create(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, def.HostConfigMaxBytes)

	body, isJSON, ok := readHostConfigBody(w, r)
	if !ok {
		return
	}

	var req hostCreateRequest
	var rawHCL []byte

	if isJSON {
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}
	} else {
		rawHCL = body
		if err := parser.ValidateHCL(rawHCL); err != nil {
			http.Error(w, fmt.Sprintf("HCL syntax error: %v", err), http.StatusBadRequest)
			return
		}

		tmpFile, err := os.CreateTemp("", "agbero_tmp_*.hcl")
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.Write(rawHCL); err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		tmpFile.Close()

		hostConfig, err := parser.ParseHostConfig(tmpFile.Name())
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to parse host config: %v", err), http.StatusBadRequest)
			return
		}
		req.Config = hostConfig
		req.Domain = r.URL.Query().Get("domain")
	}

	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	if domain == "" && req.Config != nil && len(req.Config.Domains) > 0 {
		domain = strings.ToLower(strings.TrimSpace(req.Config.Domains[0]))
	}

	if req.Config != nil {
		req.Config.Domains = []string{domain}
		woos.DefaultHost(req.Config)
	}

	// Preserve credentials the read API hid (see mergeRedactedSecrets) before
	// validation — an emptied basic_auth.users would otherwise fail Validate.
	if isJSON && req.Config != nil {
		if existing := h.discovery.Get(domain); existing != nil {
			mergeRedactedSecrets(existing, req.Config)
		}
	}

	if err := req.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if domain == "" {
		http.Error(w, "Domain is required", http.StatusBadRequest)
		return
	}
	if err := validateDomainForStorage(domain); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	overwrite := r.URL.Query().Get("overwrite")
	if overwrite == "false" || overwrite == "0" {
		if h.discovery.Get(domain) != nil {
			http.Error(w, "Domain already exists", http.StatusConflict)
			return
		}
	}

	if existingCfg := h.discovery.Get(domain); existingCfg != nil {
		if existingCfg.Protected.Active() {
			http.Error(w, "Cannot modify host with protected routes via API", http.StatusForbidden)
			return
		}
	}

	if isJSON {
		if err := h.discovery.Create(domain, req.Config); err != nil {
			h.logger.Fields("domain", domain, "err", err).Error("admin: failed to save host to disk")
			http.Error(w, "Failed to save configuration to disk", http.StatusInternalServerError)
			return
		}
	} else {
		if err := h.discovery.CreateRaw(domain, req.Config, rawHCL); err != nil {
			h.logger.Fields("domain", domain, "err", err).Error("admin: failed to save host to disk")
			http.Error(w, "Failed to save configuration to disk", http.StatusInternalServerError)
			return
		}
	}

	h.discovery.Set(domain, req.Config)
	h.logger.Fields("domain", domain).Info("admin: host created via api")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok", "message":"Discovery saved successfully"}`))
}

func (h *Host) update(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, def.HostConfigMaxBytes)

	domain := chi.URLParam(r, "domain")
	if domain == "" {
		http.Error(w, "Domain path parameter required", http.StatusBadRequest)
		return
	}
	domain = strings.ToLower(strings.TrimSpace(domain))

	validDomain, err := normalizeHostDomain(domain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	domain = validDomain

	existingCfg := h.discovery.Get(domain)
	if existingCfg == nil {
		http.Error(w, "Discovery not found", http.StatusNotFound)
		return
	}

	if existingCfg.Protected.Active() {
		http.Error(w, "Cannot modify host with protected routes via API", http.StatusForbidden)
		return
	}

	body, isJSON, ok := readHostConfigBody(w, r)
	if !ok {
		return
	}

	if isJSON {
		var req hostUpdateRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}

		if req.Config != nil {
			req.Config.Domains = []string{domain}
			woos.DefaultHost(req.Config)
			// Keep credentials the read API replaced with *** (GET -> edit -> PUT).
			mergeRedactedSecrets(existingCfg, req.Config)
		}

		if err := req.Validate(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := h.discovery.Create(domain, req.Config); err != nil {
			h.logger.Fields("domain", domain, "err", err).Error("admin: failed to save host to disk")
			http.Error(w, "Failed to save configuration to disk", http.StatusInternalServerError)
			return
		}

		h.discovery.Set(domain, req.Config)
	} else {
		// HCL
		rawHCL := body
		if err := parser.ValidateHCL(rawHCL); err != nil {
			http.Error(w, fmt.Sprintf("HCL syntax error: %v", err), http.StatusBadRequest)
			return
		}

		tmpFile, err := os.CreateTemp("", "agbero_tmp_*.hcl")
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.Write(rawHCL); err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		tmpFile.Close()

		hostConfig, err := parser.ParseHostConfig(tmpFile.Name())
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to parse host config: %v", err), http.StatusBadRequest)
			return
		}

		if hostConfig != nil {
			hostConfig.Domains = []string{domain}
			woos.DefaultHost(hostConfig)
		}

		if err := (hostUpdateRequest{Config: hostConfig}).Validate(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if existingCfg != nil && existingCfg.SourceFile != "" {
			hostConfig.SourceFile = existingCfg.SourceFile
		}

		if err := h.discovery.CreateRaw(domain, hostConfig, rawHCL); err != nil {
			h.logger.Fields("domain", domain, "err", err).Error("admin: failed to save host to disk")
			http.Error(w, "Failed to save configuration to disk", http.StatusInternalServerError)
			return
		}

		h.discovery.Set(domain, hostConfig)
	}

	h.logger.Fields("domain", domain).Info("admin: host updated via api")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok", "message":"Discovery saved successfully"}`))
}

func (h *Host) delete(w http.ResponseWriter, r *http.Request) {
	domain := chi.URLParam(r, "domain")
	if domain == "" {
		http.Error(w, "Domain path parameter required", http.StatusBadRequest)
		return
	}
	h.deleteByDomain(w, r, domain)
}

func (h *Host) deleteByDomain(w http.ResponseWriter, r *http.Request, domain string) {
	if h.discovery == nil {
		http.Error(w, "Discovery ppk not initialized", http.StatusInternalServerError)
		return
	}

	if domain == "" {
		domain = r.URL.Query().Get("domain")
	}

	if domain == "" {
		http.Error(w, "Domain query parameter required", http.StatusBadRequest)
		return
	}

	domain = strings.ToLower(strings.TrimSpace(domain))

	validDomain, err := normalizeHostDomain(domain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	domain = validDomain

	if existingCfg := h.discovery.Get(domain); existingCfg != nil {
		if existingCfg.Protected.Active() {
			http.Error(w, "Cannot modify host with protected routes via API", http.StatusForbidden)
			return
		}
	}

	if err := h.discovery.DeleteFile(domain); err != nil {
		h.logger.Fields("domain", domain, "err", err).Error("admin: failed to delete host file")
		http.Error(w, "Failed to delete host file", http.StatusInternalServerError)
		return
	}

	// Clean up the TLS cert so nothing is left orphaned on disk or in cache.
	if h.tls != nil {
		if err := h.tls.DeleteCertificate(domain); err != nil {
			// Non-fatal — host is already gone, log and continue.
			h.logger.Fields("domain", domain, "err", err).Warn("admin: failed to clean up certificate after host delete")
		}
	}

	h.logger.Fields("domain", domain).Info("admin: host deleted via api")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok", "message":"Discovery deleted successfully"}`))
}

// preview handles POST /discovery/preview.
// Accepts a JSON host config, applies defaults, validates it fully, and returns
// the resolved config rendered as HCL — exactly what would be written to disk.
// Nothing is persisted. Use this as a dry-run before create/update.
func (h *Host) preview(w http.ResponseWriter, r *http.Request) {
	// preview renders whatever it is handed, so the body must be capped just
	// like create/update — the daemon allocates the full body and amplifies it
	// through DefaultHost + the HCL renderer, and it all shares the proxy process.
	r.Body = http.MaxBytesReader(w, r.Body, def.HostConfigMaxBytes)

	var req hostCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	if req.Config == nil {
		http.Error(w, "config is required", http.StatusBadRequest)
		return
	}

	// Resolve domain the same way create does.
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	if domain == "" && len(req.Config.Domains) > 0 {
		domain = strings.ToLower(strings.TrimSpace(req.Config.Domains[0]))
	}
	req.Config.Domains = []string{domain}

	// Apply defaults so the preview reflects what would actually be stored.
	woos.DefaultHost(req.Config)

	// Full validation — same rules as create.
	if err := req.Validate(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "invalid",
			"error":  err.Error(),
		})
		return
	}

	// Render to HCL — this is what would land on disk.
	hclBytes, err := parser.MarshalBytes(req.Config)
	if err != nil {
		http.Error(w, "Failed to render HCL", http.StatusInternalServerError)
		return
	}

	// Cap the response as well: defaults and HCL formatting can amplify the
	// decoded config, and the render happens in the admin process.
	if len(hclBytes) > def.HostConfigMaxBytes {
		http.Error(w, "Rendered configuration exceeds size limit", http.StatusRequestEntityTooLarge)
		return
	}

	w.Header().Set("Content-Type", "application/hcl")
	w.Write(hclBytes)
}

// sanitizeHostConfigs returns redacted deep copies of the given host configs.
// Shared with the root package (helpers.go) via alaye.RedactHosts so the two
// admin surfaces can never apply different redaction rules — and, critically, so
// that a read-only API call can never mutate the live routing config handed out
// by discovery.LoadAll().
func sanitizeHostConfigs(hosts map[string]*alaye.Host) map[string]*alaye.Host {
	return alaye.RedactHosts(hosts)
}

// detectFormat determines the preferred response format (hcl or json) from query params or Accept header.
// It prioritizes ?format= query parameter, then falls back to Accept header inspection.
func detectFormat(r *http.Request) string {
	if format := r.URL.Query().Get("format"); format != "" {
		switch strings.ToLower(format) {
		case "hcl":
			return "hcl"
		case "json":
			return "json"
		}
	}
	if strings.Contains(r.Header.Get("Accept"), "application/hcl") {
		return "hcl"
	}
	return "json"
}

// ValidateDomainParam is chi middleware that rejects path-traversal attempts and
// malformed hostnames in {domain} route parameters before handler execution.
func ValidateDomainParam(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if domain := chi.URLParam(r, "domain"); domain != "" {
			if _, err := normalizeHostDomain(domain); err != nil {
				http.Error(w, "Invalid domain format", http.StatusBadRequest)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
