package api

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/olekukonko/ll"
)

// CertsHandler registers all certificate management API endpoints under the /certs prefix on the provided chi.Router.
// Caller should apply authentication middleware via r.Use() before or within the route group.
func CertsHandler(s *Shared, r chi.Router) {
	c := NewCerts(s)

	r.Route("/certs", func(r chi.Router) {
		r.Get("/", c.list)
		r.Post("/", c.upload)
		r.With(ValidateDomainParam).Delete("/{domain}", c.delete)
	})
}

// Certs provides HTTP handlers for listing, uploading, and deleting TLS certificates.
// It encapsulates the TLS manager, storage directory, and logger for certificate operations.
type Certs struct {
	shared   *Shared
	certsDir string
	logger   *ll.Logger
}

// NewCerts initializes a Certs instance with shared application dependencies.
// It configures the logger namespace and prepares the handler for certificate management.
func NewCerts(cfg *Shared) *Certs {
	certsDir := ""
	if state := cfg.State(); state.Global != nil {
		certsDir = state.Global.Storage.CertsDir
	}

	return &Certs{
		shared:   cfg,
		certsDir: certsDir,
		logger:   cfg.Logger.Namespace("api"),
	}
}

// list handles GET requests to retrieve all registered TLS certificates as JSON metadata.
// It scans the certificates directory and filters out internal/system certificates.
func (c *Certs) list(w http.ResponseWriter, r *http.Request) {
	ts := c.shared.State().TLSS
	if ts == nil {
		http.Error(w, "TLS manager not initialized", http.StatusInternalServerError)
		return
	}

	entries, err := os.ReadDir(c.certsDir)
	if err != nil {
		http.Error(w, "Failed to read certs directory", http.StatusInternalServerError)
		return
	}

	type CertInfo struct {
		Domain    string    `json:"domain"`
		File      string    `json:"file"`
		ExpiresAt time.Time `json:"expires_at"`
		IsExpired bool      `json:"is_expired"`
		DaysLeft  int       `json:"days_left"`
	}
	var certs []CertInfo
	seen := make(map[string]bool)
	now := time.Now()

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()

		if ts.LikelyInternal(name) {
			continue
		}

		if strings.HasSuffix(name, ".crt") || strings.HasSuffix(name, ".pem") {
			domain := strings.TrimSuffix(name, ".crt")
			domain = strings.TrimSuffix(domain, ".pem")
			domain = strings.TrimSuffix(domain, "-cert")
			domain = strings.TrimSuffix(domain, "-key")
			domain = strings.ReplaceAll(domain, "_wildcard_", "*")
			domain = strings.ReplaceAll(domain, "_wildcard", "*")

			if strings.HasPrefix(domain, "*") && !strings.HasPrefix(domain, "*.") && len(domain) > 1 {
				domain = "*" + domain[1:]
			}

			if ts.LikelyInternal(domain) || seen[domain] {
				continue
			}

			// Parse the certificate to get expiration
			certPath := filepath.Join(c.certsDir, name)
			certData, err := os.ReadFile(certPath)
			if err != nil {
				c.logger.Fields("domain", domain, "err", err).Warn("failed to read certificate")
				continue
			}

			block, _ := pem.Decode(certData)
			if block == nil {
				continue
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				c.logger.Fields("domain", domain, "err", err).Warn("failed to parse certificate")
				continue
			}

			expiresAt := cert.NotAfter
			isExpired := now.After(expiresAt)
			daysLeft := int(expiresAt.Sub(now).Hours() / 24)

			seen[domain] = true
			certs = append(certs, CertInfo{
				Domain:    domain,
				File:      name,
				ExpiresAt: expiresAt,
				IsExpired: isExpired,
				DaysLeft:  daysLeft,
			})
		}
	}

	if certs == nil {
		certs = []CertInfo{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"certificates": certs})
}

// upload handles POST requests to upload and apply a custom TLS certificate for a domain.
// It validates the JSON payload, sanitizes the domain, and delegates to the TLS manager.
func (c *Certs) upload(w http.ResponseWriter, r *http.Request) {
	ts := c.shared.State().TLSS
	if ts == nil {
		http.Error(w, "TLS manager not initialized", http.StatusInternalServerError)
		return
	}

	var req struct {
		Domain string `json:"domain"`
		Cert   string `json:"cert"`
		Key    string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	if domain == "" || req.Cert == "" || req.Key == "" {
		http.Error(w, "Domain, cert, and key are required", http.StatusBadRequest)
		return
	}

	if strings.ContainsAny(domain, "/\\") || strings.Contains(domain, "..") {
		http.Error(w, "Invalid domain string", http.StatusBadRequest)
		return
	}

	if err := ts.UpdateCertificate(domain, []byte(req.Cert), []byte(req.Key)); err != nil {
		c.logger.Fields("domain", domain, "err", err).Error("admin: failed to save custom certificate")
		http.Error(w, fmt.Sprintf("Failed to apply certificate: %v", err), http.StatusBadRequest)
		return
	}

	c.logger.Fields("domain", domain).Info("admin: custom certificate uploaded via api")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok", "message":"Certificate saved and applied successfully"}`))
}

// delete handles DELETE requests to remove a custom TLS certificate for a domain.
// It validates the domain parameter, deletes associated files, and logs the operation.
func (c *Certs) delete(w http.ResponseWriter, r *http.Request) {
	ts := c.shared.State().TLSS
	if ts == nil {
		http.Error(w, "TLS manager not initialized", http.StatusInternalServerError)
		return
	}

	domain := chi.URLParam(r, "domain")
	if domain == "" || strings.ContainsAny(domain, "/\\") || strings.Contains(domain, "..") {
		http.Error(w, "Invalid domain", http.StatusBadRequest)
		return
	}

	// Block system certs
	if domain == "ca-cert" || domain == "ca-key" || domain == "internal_auth" {
		http.Error(w, "Cannot delete system certificate", http.StatusForbidden)
		return
	}

	safeDomain := strings.ReplaceAll(domain, "*", "_wildcard_")
	basePath := filepath.Join(c.certsDir, safeDomain)

	// Delete files with error handling
	deleted := false
	for _, ext := range []string{".crt", ".key", ".key.enc"} {
		path := basePath + ext
		if err := os.Remove(path); err == nil {
			deleted = true
		} else if !os.IsNotExist(err) {
			c.logger.Fields("domain", domain, "err", err).Error("delete failed")
			http.Error(w, "Failed to delete certificate files", http.StatusInternalServerError)
			return
		}
	}

	if !deleted {
		http.Error(w, "Certificate not found", http.StatusNotFound)
		return
	}

	// Sync TLS manager
	_ = ts.DeleteCertificate(domain) // best-effort cache invalidation

	c.logger.Fields("domain", domain).Info("admin: certificate deleted")
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok","message":"Certificate deleted"}`))
}
