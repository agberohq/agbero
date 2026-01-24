package tlss

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
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/caddyserver/certmagic"
	"github.com/fsnotify/fsnotify"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/ll"
)

const (
	letsEncryptProdDir    = "https://acme-v02.api.letsencrypt.org/directory"
	letsEncryptStagingDir = "https://acme-staging-v02.api.letsencrypt.org/directory"
	acmeProfileShortLived = "shortlived"
)

type Manager struct {
	hostManager *discovery.Host
	Global      *alaye.Global

	logger     *ll.Logger
	cmMu       sync.Mutex
	cmProd     *certmagic.Config
	cmStaging  *certmagic.Config
	issProd    *certmagic.ACMEIssuer
	issStaging *certmagic.ACMEIssuer

	localMu    sync.RWMutex
	LocalCache map[string]*tls.Certificate

	Watchers  map[string]*fsnotify.Watcher
	watcherMu sync.Mutex
}

func NewManager(logger *ll.Logger, hostManager *discovery.Host, global *alaye.Global) *Manager {
	return &Manager{
		logger:      logger,
		hostManager: hostManager,
		Global:      global,
		LocalCache:  make(map[string]*tls.Certificate),
	}

}
func (m *Manager) EnsureCertMagic(next http.Handler) (http.Handler, error) {
	m.cmMu.Lock()
	defer m.cmMu.Unlock()

	if m.Global == nil {
		return next, errors.New("global config is required")
	}

	email := strings.TrimSpace(m.Global.LEEmail)
	if email == "" {
		return next, errors.New("le_email is empty")
	}

	storageDir := strings.TrimSpace(m.Global.TLSStorageDir)
	if storageDir == "" {
		return next, errors.New("tls_storage_dir is empty")
	}
	storageDir = filepath.Clean(storageDir)

	decision := func(ctx context.Context, name string) error {
		_ = ctx
		name = core.NormalizeSubject(name)
		if m.hostManager != nil && m.hostManager.Get(name) != nil {
			return nil
		}
		return errors.Newf("on-demand denied for %q", name)
	}

	if m.cmProd == nil {
		cmProd := certmagic.NewDefault()
		cmProd.OnDemand = &certmagic.OnDemandConfig{DecisionFunc: decision}
		cmProd.Storage = &certmagic.FileStorage{Path: storageDir}
		acme := certmagic.ACMEIssuer{
			Email:  email,
			Agreed: true,
			CA:     letsEncryptProdDir,
		}
		issuer := certmagic.NewACMEIssuer(cmProd, acme)
		cmProd.Issuers = []certmagic.Issuer{issuer}
		cmProd.Logger = newTLSLogger(m.logger)

		m.cmProd = cmProd
		m.issProd = issuer
	}

	if m.cmStaging == nil {
		cmStaging := certmagic.NewDefault()
		cmStaging.OnDemand = &certmagic.OnDemandConfig{DecisionFunc: decision}
		cmStaging.Storage = &certmagic.FileStorage{Path: storageDir}
		acme := certmagic.ACMEIssuer{
			Email:  email,
			Agreed: true,
			CA:     letsEncryptStagingDir,
		}
		issuer := certmagic.NewACMEIssuer(cmStaging, acme)
		cmStaging.Issuers = []certmagic.Issuer{issuer}

		m.cmStaging = cmStaging
		m.issStaging = issuer

	}

	h := next
	if m.issProd != nil {
		h = m.issProd.HTTPChallengeHandler(h)
	}
	if m.issStaging != nil {
		h = m.issStaging.HTTPChallengeHandler(h)
	}

	return h, nil
}

func (m *Manager) CmForHost(hcfg *alaye.Host) *certmagic.Config {
	if m.Global != nil && m.Global.Development {
		return m.cmStaging
	}
	if hcfg != nil && &hcfg.TLS != nil {
		if hcfg.TLS.LetsEncrypt.Staging {
			return m.cmStaging
		}
	}
	return m.cmProd
}

func (m *Manager) GetLocalCertificate(local alaye.LocalCert, host string) (*tls.Certificate, error) {
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

	m.startLocalWatcher(cacheKey, certFile, keyFile, host)
	return &cert, nil
}

func (m *Manager) GetAutoLocalCertificate(host string) (*tls.Certificate, error) {
	cacheKey := "auto|" + host

	m.localMu.RLock()
	if c := m.LocalCache[cacheKey]; c != nil {
		m.localMu.RUnlock()
		return c, nil
	}
	m.localMu.RUnlock()

	// Instantiate Installer
	installer := NewInstaller(m.logger)
	installer.SetHosts([]string{host}, 443) // Default to 443 for naming

	// Generate or Load
	certFile, keyFile, err := installer.EnsureLocalhostCert()
	if err != nil {
		return nil, errors.Newf("auto-tls generation failed for %q: %w", host, err)
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, errors.Newf("failed to load auto-generated cert for %q: %w", host, err)
	}

	m.localMu.Lock()
	m.LocalCache[cacheKey] = &cert
	m.localMu.Unlock()

	// Watch these files too in case user regenerates them
	m.startLocalWatcher(cacheKey, certFile, keyFile, host)

	return &cert, nil
}

func (m *Manager) startLocalWatcher(cacheKey, certFile, keyFile, host string) {
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
		m.logger.Fields("err", err, "host", host).Warn("failed to create local cert watcher")
		return
	}

	for _, file := range []string{certFile, keyFile} {
		if err := watcher.Add(file); err != nil {
			m.logger.Fields("err", err, "file", file, "host", host).Warn("failed to watch local cert file")
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
				m.logger.Fields("err", err, "host", host).Error("local cert watcher error")
			}
		}
	}()
}

func (m *Manager) invalidateLocal(cacheKey, host string) {
	m.localMu.Lock()
	delete(m.LocalCache, cacheKey)
	m.localMu.Unlock()
	m.logger.Fields("host", host, "key", cacheKey).Info("local cert invalidated; will reload on next request")
}

func (m *Manager) GetCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if chi == nil || chi.ServerName == "" {
		return nil, errors.New("missing SNI")
	}

	sni := core.NormalizeSubject(chi.ServerName)
	if net.ParseIP(sni) != nil {
		// Just log, continue logic
	}

	hcfg := m.hostManager.Get(sni)
	if hcfg == nil {
		return nil, errors.Newf("unknown host %q", sni)
	}

	var mode alaye.TlsMode
	if &hcfg.TLS != nil && hcfg.TLS.Mode != "" {
		mode = hcfg.TLS.Mode
	} else {
		// Smart Default
		if core.IsLocalhost(sni) {
			mode = alaye.ModeLocalAuto
		} else {
			mode = alaye.ModeLetsEncrypt
		}
	}

	switch mode {
	case alaye.ModeLocalNone:
		return nil, errors.Newf("tls disabled for host %q", sni)

	case alaye.ModeLocalCert:
		if &hcfg.TLS == nil {
			return nil, errors.Newf("tls=local requires tls block for host %q", sni)
		}
		return m.GetLocalCertificate(hcfg.TLS.Local, sni)

	case alaye.ModeLocalAuto:
		return m.GetAutoLocalCertificate(sni)

	case alaye.ModeLetsEncrypt:
		cm := m.CmForHost(hcfg)
		if cm == nil {
			return nil, errors.Newf("letsencrypt not enabled globally (host %q)", sni)
		}
		if &hcfg.TLS != nil && hcfg.TLS.LetsEncrypt.ShortLived {
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

	case alaye.ModeCustomCA:
		if &hcfg.TLS == nil || hcfg.TLS.CustomCA.Root == "" {
			return nil, errors.Newf("tls=custom_ca requires root cert for host %q", sni)
		}
		return m.getCustomCACert(hcfg.TLS.CustomCA.Root, sni)

	default:
		return nil, errors.Newf("unknown tls mode %q for host %q", mode, sni)
	}
}

func (m *Manager) getCustomCACert(root string, host string) (*tls.Certificate, error) {
	caCert, err := os.ReadFile(root)
	if err != nil {
		return nil, errors.Newf("load custom CA root (host=%q): %w", host, err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, errors.Newf("invalid custom CA PEM (host=%q)", host)
	}
	if hcfg := m.hostManager.Get(host); hcfg != nil && &hcfg.TLS != nil {
		return m.GetLocalCertificate(hcfg.TLS.Local, host)
	}
	return nil, errors.Newf("custom_ca requires local cert/key for host %q", host)
}

func (m *Manager) Close() {
	m.watcherMu.Lock()
	defer m.watcherMu.Unlock()
	for key, w := range m.Watchers {
		w.Close()
		delete(m.Watchers, key)
	}
}
