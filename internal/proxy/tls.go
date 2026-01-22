// internal/proxy/tls.go
package proxy

import (
	"context"
	"crypto/tls"
	"net/http"
	"path/filepath"
	"strings"
	"sync"

	"git.imaxinacion.net/aibox/agbero/internal/config"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"github.com/caddyserver/certmagic"
	"github.com/olekukonko/errors"
)

const (
	letsEncryptProdDir    = "https://acme-v02.api.letsencrypt.org/directory"
	letsEncryptStagingDir = "https://acme-staging-v02.api.letsencrypt.org/directory"

	// Let's Encrypt 6-day profile name (ACME profile)
	acmeProfileShortLived = "shortlived"
)

type tlsManager struct {
	logger      anyLogger
	hostManager *discovery.Host
	global      *config.GlobalConfig

	// CertMagic configs (prod + staging)
	cmMu       sync.Mutex
	cmProd     *certmagic.Config
	cmStaging  *certmagic.Config
	issProd    *certmagic.ACMEIssuer
	issStaging *certmagic.ACMEIssuer

	// cache local certs by "certPath|keyPath"
	localMu    sync.RWMutex
	localCache map[string]*tls.Certificate
}

// ensureCertMagic prepares CertMagic configs. It returns an HTTP handler that serves
// HTTP-01 challenges for both prod and staging issuers.
func (m *tlsManager) ensureCertMagic(next http.Handler) (http.Handler, error) {
	m.cmMu.Lock()
	defer m.cmMu.Unlock()

	if m.global == nil {
		return next, errors.New("global config is required")
	}

	email := strings.TrimSpace(m.global.LEEmail)
	if email == "" {
		return next, errors.New("le_email is empty")
	}

	decision := func(ctx context.Context, name string) error {
		_ = ctx
		name = normalizeSubject(name)
		if m.hostManager != nil && m.hostManager.Get(name) != nil {
			return nil
		}
		return errors.Newf("on-demand denied for %q", name)
	}

	// Create (or reuse) prod config
	if m.cmProd == nil {
		cmProd := certmagic.NewDefault()
		cmProd.OnDemand = &certmagic.OnDemandConfig{DecisionFunc: decision}

		acme := certmagic.ACMEIssuer{
			Email:  email,
			Agreed: true,
			CA:     letsEncryptProdDir,
		}
		// Optional: enable short-lived later
		// acme.Profile = acmeProfileShortLived

		issuer := certmagic.NewACMEIssuer(cmProd, acme)
		cmProd.Issuers = []certmagic.Issuer{issuer}

		m.cmProd = cmProd
		m.issProd = issuer
	}

	// Create (or reuse) staging config
	if m.cmStaging == nil {
		cmStaging := certmagic.NewDefault()
		cmStaging.OnDemand = &certmagic.OnDemandConfig{DecisionFunc: decision}

		acme := certmagic.ACMEIssuer{
			Email:  email,
			Agreed: true,
			CA:     letsEncryptStagingDir,
		}
		// Optional: enable short-lived later
		// acme.Profile = acmeProfileShortLived

		issuer := certmagic.NewACMEIssuer(cmStaging, acme)
		cmStaging.Issuers = []certmagic.Issuer{issuer}

		m.cmStaging = cmStaging
		m.issStaging = issuer
	}

	// Build HTTP-01 handler stack to serve challenges for both issuers.
	h := next
	if m.issProd != nil {
		h = m.issProd.HTTPChallengeHandler(h)
	}
	if m.issStaging != nil {
		h = m.issStaging.HTTPChallengeHandler(h)
	}

	return h, nil
}

func (m *tlsManager) cmForHost(hcfg *config.HostConfig) *certmagic.Config {
	// Global dev mode forces staging
	if m.global != nil && m.global.Development {
		return m.cmStaging
	}

	// Per-host override
	if hcfg != nil && hcfg.TLS != nil {
		if hcfg.TLS.LetsEncrypt.Staging {
			return m.cmStaging
		}
	}
	return m.cmProd
}

func (m *tlsManager) getLocalCertificate(local config.LocalCert, host string) (*tls.Certificate, error) {
	certFile := strings.TrimSpace(local.CertFile)
	keyFile := strings.TrimSpace(local.KeyFile)

	if certFile == "" || keyFile == "" {
		return nil, errors.Newf("local tls requires cert_file and key_file (host=%q)", host)
	}

	certFile = filepath.Clean(certFile)
	keyFile = filepath.Clean(keyFile)
	cacheKey := certFile + "|" + keyFile

	m.localMu.RLock()
	if c := m.localCache[cacheKey]; c != nil {
		m.localMu.RUnlock()
		return c, nil
	}
	m.localMu.RUnlock()

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, errors.Newf("load local cert (host=%q): %w", host, err)
	}

	m.localMu.Lock()
	m.localCache[cacheKey] = &cert
	m.localMu.Unlock()

	return &cert, nil
}
