package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/hub/discovery"
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
		r.With(ValidateDomainParam).Get("/{domain}", h.get)
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
}

// NewHost initializes a Host instance with shared application dependencies.
// It configures the logger namespace and prepares the handler for host management.
func NewHost(cfg *Shared) *Host {
	return &Host{
		discovery: cfg.Discovery,
		hostsDir:  cfg.State().Global.Storage.HostsDir,
		logger:    cfg.Logger.Namespace("api"),
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
		e := expect.NewRaw(r.Domain)
		if _, err := e.Domain(); err != nil {
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
	hosts, _ := h.discovery.LoadAll()
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

	e := expect.NewRaw(domain)
	validDomain, err := e.Domain()
	if err != nil {
		http.Error(w, "Invalid domain format", http.StatusBadRequest)
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
			filename = zulu.NormalizeHost(domain) + woos.HCLSuffix
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

// create handles POST requests to register a new host configuration via JSON payload.
func (h *Host) create(w http.ResponseWriter, r *http.Request) {
	contentType := r.Header.Get("Content-Type")
	isJSON := strings.Contains(contentType, "application/json") || contentType == ""

	var req hostCreateRequest
	var rawHCL []byte
	var err error

	if isJSON {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}
	} else {
		rawHCL, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}
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

	if err := req.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if domain == "" {
		http.Error(w, "Domain is required", http.StatusBadRequest)
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
	domain := chi.URLParam(r, "domain")
	if domain == "" {
		http.Error(w, "Domain path parameter required", http.StatusBadRequest)
		return
	}
	domain = strings.ToLower(strings.TrimSpace(domain))

	e := expect.NewRaw(domain)
	validDomain, err := e.Domain()
	if err != nil {
		http.Error(w, "Invalid domain format", http.StatusBadRequest)
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

	contentType := r.Header.Get("Content-Type")
	isJSON := strings.Contains(contentType, "application/json")

	if isJSON {
		var req hostUpdateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}

		if req.Config != nil {
			req.Config.Domains = []string{domain}
			woos.DefaultHost(req.Config)
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
		rawHCL, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}

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

	e := expect.NewRaw(domain)
	validDomain, err := e.Domain()
	if err != nil {
		http.Error(w, "Invalid domain format", http.StatusBadRequest)
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

	h.logger.Fields("domain", domain).Info("admin: host deleted via api")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok", "message":"Discovery deleted successfully"}`))
}

// sanitizeHostConfigs redacts sensitive fields from host configurations before JSON serialization.
// It clones the input map and clears credential fields from all routes to prevent leakage.
func sanitizeHostConfigs(hosts map[string]*alaye.Host) map[string]*alaye.Host {
	out := make(map[string]*alaye.Host, len(hosts))
	for k, v := range hosts {
		if v == nil {
			continue
		}
		clone := *v
		for i := range clone.Routes {
			sanitizeRouteConfig(&clone.Routes[i])
		}
		out[k] = &clone
	}
	return out
}

// sanitizeRouteConfig clears sensitive credential fields from a route configuration before API exposure.
// Extend this function as new sensitive fields are added to alaye.Route to maintain security.
func sanitizeRouteConfig(route *alaye.Route) {
	route.BasicAuth.Users = nil
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

// ValidateDomainParam is chi middleware that rejects path-traversal attempts in {domain} route parameters.
// It validates the domain segment before handler execution and returns 400 for unsafe values.
func ValidateDomainParam(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if domain := chi.URLParam(r, "domain"); domain != "" {

			e := expect.NewRaw(domain)
			if _, err := e.Domain(); err != nil && domain != "localhost" {
				http.Error(w, "Invalid domain format", http.StatusBadRequest)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
