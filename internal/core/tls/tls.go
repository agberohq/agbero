// internal/core/tls/tls.go
package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"git.imaxinacion.net/aibox/agbero/internal/core"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"github.com/caddyserver/certmagic"
	"github.com/fsnotify/fsnotify"
	"github.com/olekukonko/errors"
)

const (
	letsEncryptProdDir    = "https://acme-v02.api.letsencrypt.org/directory"
	letsEncryptStagingDir = "https://acme-staging-v02.api.letsencrypt.org/directory"

	// Let's Encrypt 6-day profile name (ACME profile)
	acmeProfileShortLived = "shortlived"
)

type TlsManager struct {
	Logger      woos.TlsLogger
	HostManager *discovery.Host
	Global      *woos.GlobalConfig

	// CertMagic configs (prod + staging)
	cmMu       sync.Mutex
	cmProd     *certmagic.Config
	cmStaging  *certmagic.Config
	issProd    *certmagic.ACMEIssuer
	issStaging *certmagic.ACMEIssuer

	// cache local certs by "certPath|keyPath"
	localMu    sync.RWMutex
	LocalCache map[string]*tls.Certificate

	// Watchers for local cert files (key: cacheKey, value: *fsnotify.Watcher)
	Watchers  map[string]*fsnotify.Watcher
	watcherMu sync.Mutex
}

// EnsureCertMagic prepares CertMagic configs. It returns an HTTP handler that serves
// HTTP-01 challenges for both prod and staging issuers.
//
// IMPORTANT (production): CertMagic storage must be persistent (especially in containers).
// We honor Global config TLSStorageDir and wire it into certmagic.
func (m *TlsManager) EnsureCertMagic(next http.Handler) (http.Handler, error) {
	m.cmMu.Lock()
	defer m.cmMu.Unlock()

	if m.Global == nil {
		return next, errors.New("global config is required")
	}

	email := strings.TrimSpace(m.Global.LEEmail)
	if email == "" {
		return next, errors.New("le_email is empty")
	}

	// Persistent storage directory (config-driven; defaults applied by config.ApplyDefaults)
	storageDir := strings.TrimSpace(m.Global.TLSStorageDir)
	if storageDir == "" {
		return next, errors.New("tls_storage_dir is empty")
	}
	storageDir = filepath.Clean(storageDir)

	decision := func(ctx context.Context, name string) error {
		_ = ctx
		name = core.NormalizeSubject(name)

		// Gate on-demand issuance strictly to configured domains.
		// hostManager.Get already matches configured domains.
		if m.HostManager != nil && m.HostManager.Get(name) != nil {
			return nil
		}
		return errors.Newf("on-demand denied for %q", name)
	}

	// Create (or reuse) prod config
	if m.cmProd == nil {
		cmProd := certmagic.NewDefault()
		cmProd.OnDemand = &certmagic.OnDemandConfig{DecisionFunc: decision}
		cmProd.Storage = &certmagic.FileStorage{Path: storageDir}

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
		cmStaging.Storage = &certmagic.FileStorage{Path: storageDir}

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

func (m *TlsManager) CmForHost(hcfg *woos.HostConfig) *certmagic.Config {
	// Global dev mode forces staging
	if m.Global != nil && m.Global.Development {
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

func (m *TlsManager) GetLocalCertificate(local woos.LocalCert, host string) (*tls.Certificate, error) {
	certFile := strings.TrimSpace(local.CertFile)
	keyFile := strings.TrimSpace(local.KeyFile)

	if certFile == "" || keyFile == "" {
		return nil, errors.Newf("local tls requires cert_file and key_file (host=%q)", host)
	}

	certFile = filepath.Clean(certFile)
	keyFile = filepath.Clean(keyFile)
	cacheKey := certFile + "|" + keyFile

	m.localMu.RLock()
	if c := m.LocalCache[cacheKey]; c != nil {
		m.localMu.RUnlock()
		return c, nil
	}
	m.localMu.RUnlock()

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, errors.Newf("load local cert (host=%q): %w", host, err)
	}

	m.localMu.Lock()
	m.LocalCache[cacheKey] = &cert
	m.localMu.Unlock()

	// Start watcher if not already
	m.startLocalWatcher(cacheKey, certFile, keyFile, host)

	return &cert, nil
}

// startLocalWatcher sets up fsnotify for cert/key files
func (m *TlsManager) startLocalWatcher(cacheKey, certFile, keyFile, host string) {
	m.watcherMu.Lock()
	defer m.watcherMu.Unlock()

	if m.Watchers == nil {
		m.Watchers = make(map[string]*fsnotify.Watcher)
	}

	if _, exists := m.Watchers[cacheKey]; exists {
		return
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		m.Logger.Fields("err", err, "host", host).Warn("failed to create local cert watcher")
		return
	}

	// Watch cert and key files
	for _, file := range []string{certFile, keyFile} {
		if err := watcher.Add(file); err != nil {
			m.Logger.Fields("err", err, "file", file, "host", host).Warn("failed to watch local cert file")
			watcher.Close()
			return
		}
	}

	m.Watchers[cacheKey] = watcher

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Rename) {
					m.invalidateLocal(cacheKey, host)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				m.Logger.Fields("err", err, "host", host).Error("local cert watcher error")
			}
		}
	}()
}

// invalidateLocal removes cache entry on file change
func (m *TlsManager) invalidateLocal(cacheKey, host string) {
	m.localMu.Lock()
	delete(m.LocalCache, cacheKey)
	m.localMu.Unlock()

	m.Logger.Fields("host", host, "key", cacheKey).Info("local cert invalidated; will reload on next request")
}

func (m *TlsManager) GetCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if chi == nil || chi.ServerName == "" {
		return nil, errors.New("missing SNI")
	}

	sni := core.NormalizeSubject(chi.ServerName)
	if net.ParseIP(sni) != nil {
		m.Logger.Fields("sni", sni).Error("handling IP SNI for cert")
	}

	hcfg := m.HostManager.Get(sni)
	if hcfg == nil {
		return nil, errors.Newf("unknown host %q", sni)
	}

	mode := woos.ModeLetsEncrypt
	if hcfg.TLS != nil && hcfg.TLS.Mode != "" {
		mode = hcfg.TLS.Mode
	}

	switch mode {
	case woos.ModeLocalNone:
		return nil, errors.Newf("tls disabled for host %q", sni)

	case woos.ModeLocalCert:
		if hcfg.TLS == nil {
			return nil, errors.Newf("tls=local requires tls block for host %q", sni)
		}
		return m.GetLocalCertificate(hcfg.TLS.Local, sni)

	case woos.ModeLetsEncrypt:
		cm := m.CmForHost(hcfg)
		if cm == nil {
			return nil, errors.Newf("letsencrypt not enabled globally (host %q)", sni)
		}

		// Apply short-lived if configured
		if hcfg.TLS != nil && hcfg.TLS.LetsEncrypt.ShortLived {
			for _, iss := range cm.Issuers {
				if acmeIss, ok := iss.(*certmagic.ACMEIssuer); ok {
					acmeIss.Profile = acmeProfileShortLived
				}
			}
		}

		cmTLS := cm.TLSConfig()
		chi2 := *chi
		chi2.ServerName = sni
		return cmTLS.GetCertificate(&chi2)

	case "custom_ca":
		if hcfg.TLS == nil || hcfg.TLS.CustomCA.Root == "" {
			return nil, errors.Newf("tls=custom_ca requires root cert for host %q", sni)
		}
		return m.getCustomCACert(hcfg.TLS.CustomCA.Root, sni)

	default:
		return nil, errors.Newf("unknown tls mode %q for host %q", mode, sni)
	}
}

// getCustomCACert loads cert from custom CA (e.g., mkcert)
func (m *TlsManager) getCustomCACert(root string, host string) (*tls.Certificate, error) {
	// For simplicity, assume root is CA cert file; use certmagic.CustomCAIssuer
	caCert, err := os.ReadFile(root)
	if err != nil {
		return nil, errors.Newf("load custom CA root (host=%q): %w", host, err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, errors.Newf("invalid custom CA PEM (host=%q)", host)
	}

	// Here, for full custom CA, you'd generate/issue certs, but assuming pre-issued like mkcert,
	// fallback to local load (reuse GetLocalCertificate if cert/key provided, else error)
	if hcfg := m.HostManager.Get(host); hcfg != nil && hcfg.TLS != nil {
		return m.GetLocalCertificate(hcfg.TLS.Local, host)
	}
	return nil, errors.Newf("custom_ca requires local cert/key for host %q", host)
}

// Close stops all Watchers (call on shutdown)
func (m *TlsManager) Close() {
	m.watcherMu.Lock()
	defer m.watcherMu.Unlock()

	for key, w := range m.Watchers {
		w.Close()
		delete(m.Watchers, key)
	}
}
