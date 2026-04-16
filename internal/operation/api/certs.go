package api

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/olekukonko/ll"
)

// CertsHandler registers all certificate management API endpoints under /certs.
// Caller must apply authentication middleware before mounting.
func CertsHandler(s *Shared, r chi.Router) {
	c := NewCerts(s)

	r.Route("/certs", func(r chi.Router) {
		r.Get("/", c.list)
		r.Post("/", c.upload)
		r.With(ValidateDomainParam).Delete("/{domain}", c.delete)
	})
}

// Certs provides HTTP handlers for listing, uploading, and deleting TLS certificates.
type Certs struct {
	shared *Shared
	logger *ll.Logger
}

func NewCerts(cfg *Shared) *Certs {
	return &Certs{
		shared: cfg,
		logger: cfg.Logger.Namespace("api/certs"),
	}
}

// list handles GET /certs.
//
// Certificates are stored by the tlsstore backend (keeper, disk, or memory) under
// issuer subdirectories — not as flat files in the root certsDir. This handler
// asks the TLS manager's storage for the canonical domain list, then loads each
// certificate to extract the expiry metadata.
func (c *Certs) list(w http.ResponseWriter, r *http.Request) {
	ts := c.shared.State().TLSS
	if ts == nil {
		http.Error(w, "TLS manager not initialized", http.StatusInternalServerError)
		return
	}

	domains, err := ts.ListCertificates()
	if err != nil {
		http.Error(w, "Failed to list certificates", http.StatusInternalServerError)
		return
	}

	type CertInfo struct {
		Domain       string    `json:"domain"`
		IssuedAt     time.Time `json:"issued_at"`
		ExpiresAt    time.Time `json:"expires_at"`
		IsExpired    bool      `json:"is_expired"`
		DaysLeft     int       `json:"days_left"`
		Issuer       string    `json:"issuer"`
		Subject      string    `json:"subject"`
		SANs         []string  `json:"sans"`
		KeyType      string    `json:"key_type"`
		KeyBits      int       `json:"key_bits,omitempty"`
		SerialNumber string    `json:"serial_number"`
		Source       string    `json:"source"` // "local_auto" | "letsencrypt" | "custom"
	}

	now := time.Now()
	certs := make([]CertInfo, 0, len(domains))
	seen := make(map[string]bool)

	for _, domain := range domains {
		if ts.LikelyInternal(domain) || seen[domain] {
			continue
		}
		seen[domain] = true

		certPEM, _, loadErr := ts.LoadCertificate(domain)
		if loadErr != nil || len(certPEM) == 0 {
			continue
		}

		block, _ := pem.Decode(certPEM)
		if block == nil {
			continue
		}
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			c.logger.Fields("domain", domain, "err", parseErr).Warn("failed to parse certificate")
			continue
		}

		// SANs: DNS names + IP addresses
		sans := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses))
		sans = append(sans, cert.DNSNames...)
		for _, ip := range cert.IPAddresses {
			sans = append(sans, ip.String())
		}

		// Key type and size
		keyType, keyBits := certKeyInfo(cert)

		// Source heuristic based on issuer
		source := certSource(cert)

		certs = append(certs, CertInfo{
			Domain:       domain,
			IssuedAt:     cert.NotBefore,
			ExpiresAt:    cert.NotAfter,
			IsExpired:    now.After(cert.NotAfter),
			DaysLeft:     int(cert.NotAfter.Sub(now).Hours() / 24),
			Issuer:       cert.Issuer.CommonName,
			Subject:      cert.Subject.CommonName,
			SANs:         sans,
			KeyType:      keyType,
			KeyBits:      keyBits,
			SerialNumber: fmt.Sprintf("%X", cert.SerialNumber),
			Source:       source,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"certificates": certs})
}

// certKeyInfo returns the key algorithm and bit size from a certificate's public key.
func certKeyInfo(cert *x509.Certificate) (string, int) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pub.Size() * 8
	case *ecdsa.PublicKey:
		return "ECDSA", pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		return "unknown", 0
	}
}

// certSource identifies how a cert was issued based on issuer fields.
func certSource(cert *x509.Certificate) string {
	issuerCN := strings.ToLower(cert.Issuer.CommonName)
	issuerOrg := ""
	if len(cert.Issuer.Organization) > 0 {
		issuerOrg = strings.ToLower(cert.Issuer.Organization[0])
	}
	switch {
	case strings.Contains(issuerCN, "let's encrypt") ||
		strings.Contains(issuerOrg, "let's encrypt") ||
		strings.Contains(issuerCN, "letsencrypt") ||
		strings.Contains(issuerOrg, "letsencrypt"):
		return "letsencrypt"
	case strings.Contains(issuerCN, "development ca") ||
		strings.Contains(issuerOrg, "agbero"):
		return "local_auto"
	default:
		return "custom"
	}
}

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
		c.logger.Fields("domain", domain, "err", err).Error("failed to save custom certificate")
		http.Error(w, fmt.Sprintf("Failed to apply certificate: %v", err), http.StatusBadRequest)
		return
	}

	c.logger.Fields("domain", domain).Info("custom certificate uploaded via API")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok","message":"Certificate saved and applied successfully"}`))
}

// delete handles DELETE /certs/{domain}.
// Delegates entirely to the TLS manager which clears both the cache and the
// backing store (keeper, disk, or memory).
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
	if ts.LikelyInternal(domain) {
		http.Error(w, "Cannot delete system certificate", http.StatusForbidden)
		return
	}

	if err := ts.DeleteCertificate(domain); err != nil {
		c.logger.Fields("domain", domain, "err", err).Error("failed to delete certificate")
		http.Error(w, "Failed to delete certificate: "+err.Error(), http.StatusInternalServerError)
		return
	}

	c.logger.Fields("domain", domain).Info("certificate deleted via API")
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok","message":"Certificate deleted"}`))
}
