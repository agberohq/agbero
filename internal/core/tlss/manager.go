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
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/caddyserver/certmagic"
	"github.com/fsnotify/fsnotify"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/ll"
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

	watcher   *fsnotify.Watcher
	watchList map[string]func()
	watcherMu sync.Mutex
}

func NewManager(logger *ll.Logger, hostManager *discovery.Host, global *alaye.Global) *Manager {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logger.Fatal(err)
	}
	m := &Manager{
		logger:      logger,
		hostManager: hostManager,
		Global:      global,
		LocalCache:  make(map[string]*tls.Certificate),
		watchList:   make(map[string]func()),
		watcher:     watcher,
	}

	go m.globalWatchLoop()
	return m

}

func (m *Manager) startLocalWatcher(cacheKey, certFile, keyFile, host string) {
	m.watcherMu.Lock()
	defer m.watcherMu.Unlock()

	// Add files to the single watcher
	m.watcher.Add(certFile)
	m.watcher.Add(keyFile)

	// Register callback for these paths
	callback := func() { m.invalidateLocal(cacheKey, host) }
	m.watchList[certFile] = callback
	m.watchList[keyFile] = callback
}

func (m *Manager) globalWatchLoop() {
	for {
		select {
		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				m.watcherMu.Lock()
				if callback, exists := m.watchList[event.Name]; exists {
					// Run in goroutine to not block watcher
					go callback()
				}
				m.watcherMu.Unlock()
			}
		case <-m.watcher.Errors:
			return
		}
	}
}

func (m *Manager) EnsureCertMagic(next http.Handler) (http.Handler, error) {
	m.cmMu.Lock()
	defer m.cmMu.Unlock()

	if m.Global == nil {
		return next, woos.ErrGlobalConfigRequired
	}

	email := strings.TrimSpace(m.Global.LetsEncrypt.Email)
	if email == "" {
		return next, woos.ErrEmptyLEEmail
	}

	storageDir := strings.TrimSpace(m.Global.Storage.CertsDir)
	if storageDir == "" {
		return next, woos.ErrEmptyCertFile
	}
	storageDir = filepath.Clean(storageDir)

	decision := func(ctx context.Context, name string) error {
		_ = ctx
		name = core.NormalizeSubject(name)

		// Strict Check: Only issue certs for explicitly configured domains.
		hcfg := m.hostManager.Get(name)
		if hcfg == nil {
			return errors.Newf("%w for %q (host not configured)", woos.ErrOnDemandDenied, name)
		}

		// Mode check: If this host is configured as a Tunnel Client,
		// we MUST NOT attempt ACME issuance. The laptop cannot solve challenges.
		if hcfg.Tunnel != nil && hcfg.Tunnel.Client != nil && hcfg.Tunnel.Client.Enabled {
			return errors.Newf("acme denied for tunnel client host: %q", name)
		}

		return nil
	}

	if m.cmProd == nil {
		cmProd := certmagic.NewDefault()
		cmProd.OnDemand = &certmagic.OnDemandConfig{
			DecisionFunc: decision,
		}
		cmProd.Storage = &certmagic.FileStorage{Path: storageDir}
		acme := certmagic.ACMEIssuer{
			Email:  email,
			Agreed: true,
			CA:     woos.LetsEncryptProdDir,
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
			Email:                   email,
			Agreed:                  true,
			CA:                      woos.LetsEncryptStagingDir,
			DisableTLSALPNChallenge: true,
		}
		issuer := certmagic.NewACMEIssuer(cmStaging, acme)
		cmStaging.Issuers = []certmagic.Issuer{issuer}

		m.cmStaging = cmStaging
		m.issStaging = issuer
	}

	h := next

	useStaging := m.Global != nil && m.Global.LetsEncrypt.Staging

	if useStaging {
		if m.issStaging != nil {
			h = m.issStaging.HTTPChallengeHandler(h)
		}
	} else {
		if m.issProd != nil {
			h = m.issProd.HTTPChallengeHandler(h)
		}
	}

	return h, nil
}

func (m *Manager) CmForHost(hcfg *alaye.Host) *certmagic.Config {
	useStaging := false
	if m.Global != nil {
		useStaging = m.Global.LetsEncrypt.Staging
	}

	if hcfg != nil {
		if hcfg.TLS.LetsEncrypt.Staging {
			useStaging = true
		}
	}

	if useStaging {
		return m.cmStaging
	}
	return m.cmProd
}

func (m *Manager) GetLocalCertificate(local alaye.LocalCert, host string) (*tls.Certificate, error) {
	certFile := strings.TrimSpace(local.CertFile)
	keyFile := strings.TrimSpace(local.KeyFile)

	if certFile == "" || keyFile == "" {
		return nil, errors.Newf("%w (host=%q)", woos.ErrLocalTLSMissingFiles, host)
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

	//m.startLocalWatcher(cacheKey, certFile, keyFile, host)
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

	installer := NewInstaller(m.logger, woos.MakeFolder(m.Global.Storage.CertsDir, woos.CertDir))
	installer.SetHosts([]string{host}, woos.DefaultHTTPSPort)

	certFile, keyFile, err := installer.EnsureLocalhostCert()
	if err != nil {
		return nil, errors.Newf("auto-tls failed for %q: %w", host, err)
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, errors.Newf("load cert failed for %q: %w", host, err)
	}

	m.localMu.Lock()
	m.LocalCache[cacheKey] = &cert
	m.localMu.Unlock()

	m.startLocalWatcher(cacheKey, certFile, keyFile, host)

	return &cert, nil
}

func (m *Manager) invalidateLocal(cacheKey, host string) {
	m.localMu.Lock()
	delete(m.LocalCache, cacheKey)
	m.localMu.Unlock()
	m.logger.Fields("host", host, "key", cacheKey).Info("local cert invalidated; will reload on next request")
}

func (m *Manager) GetCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if chi == nil || strings.TrimSpace(chi.ServerName) == "" {
		return nil, errors.New("missing SNI")
	}

	sni := core.NormalizeHost(chi.ServerName)
	if sni == "" {
		return nil, woos.ErrMissingSNI
	}

	if net.ParseIP(sni) != nil {
		return nil, nil
	}

	hcfg := m.hostManager.Get(sni)
	if hcfg == nil {
		return nil, errors.Newf("%w %q", woos.ErrUnknownHost, sni)
	}

	mode := hcfg.TLS.Mode
	if strings.TrimSpace(string(mode)) == "" {
		if core.IsLocalhost(sni) {
			mode = alaye.ModeLocalAuto
		} else {
			mode = alaye.ModeLetsEncrypt
		}
	}

	// Force Disable TLS if Tunnel Client is enabled on this host
	// This prevents laptops from trying to issue certs for "blog.tunnel.agbero.com"
	if hcfg.Tunnel != nil && hcfg.Tunnel.Client != nil && hcfg.Tunnel.Client.Enabled {
		mode = alaye.ModeLocalNone
	}

	switch mode {
	case alaye.ModeLocalNone:
		// Return nil error to allow handshake to proceed with default cert or fail gracefully at TCP level,
		// but typically we want to signal "No Cert".
		// However, returning an error here aborts the handshake immediately.
		return nil, errors.Newf("%w: tls disabled for host %q", woos.ErrTLSDisabled, sni)

	case alaye.ModeLocalCert:
		if strings.TrimSpace(hcfg.TLS.Local.CertFile) == "" || strings.TrimSpace(hcfg.TLS.Local.KeyFile) == "" {
			return nil, errors.Newf("%w %q", woos.ErrLocalCertMissingFiles, sni)
		}
		return m.GetLocalCertificate(hcfg.TLS.Local, sni)

	case alaye.ModeLocalAuto:
		if !core.IsLocalhost(sni) {
			return nil, errors.Newf("%w (got %q)", woos.ErrLocalAutoNotAllowed, sni)
		}
		return m.GetAutoLocalCertificate(sni)

	case alaye.ModeLetsEncrypt:
		cm := m.CmForHost(hcfg)
		if cm == nil {
			return nil, errors.Newf("%w(host %q)", woos.ErrLetsEncryptNotEnabled, sni)
		}

		if hcfg.TLS.LetsEncrypt.ShortLived {
			for _, iss := range cm.Issuers {
				if acmeIss, ok := iss.(*certmagic.ACMEIssuer); ok {
					acmeIss.Profile = woos.AcmeProfileShortLived
				}
			}
		}

		cmTLS := cm.TLSConfig()
		chi2 := *chi
		chi2.ServerName = sni
		return cmTLS.GetCertificate(&chi2)

	case alaye.ModeCustomCA:
		if strings.TrimSpace(hcfg.TLS.CustomCA.Root) == "" {
			return nil, errors.Newf("%w for host %q", woos.ErrCustomCAMissingRoot, sni)
		}
		return m.getCustomCACert(hcfg.TLS.CustomCA.Root, sni)

	default:
		return nil, errors.Newf("%w: %q for host %q", woos.ErrUnknownTLSMode, mode, sni)
	}
}

func (m *Manager) getCustomCACert(root string, host string) (*tls.Certificate, error) {
	caCert, err := os.ReadFile(root)
	if err != nil {
		return nil, errors.Newf("%w: (host=%q): %w", woos.ErrLoadCustomCARoot, host, err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, errors.Newf("%w:(host=%q)", woos.ErrInvalidCustomCAPEM, host)
	}
	if hcfg := m.hostManager.Get(host); hcfg != nil {
		if hcfg.TLS.Local.CertFile == "" || hcfg.TLS.Local.KeyFile == "" {
			return nil, errors.Newf("%w for host %q", woos.ErrCustomCALocalCertRequired, host)
		}
		return m.GetLocalCertificate(hcfg.TLS.Local, host)
	}
	return nil, errors.Newf("%w for host %q", woos.ErrUnknownHost, host)
}

func (m *Manager) Close() {
	m.watcherMu.Lock()
	defer m.watcherMu.Unlock()
	m.watcher.Close()
}

func (m *Manager) ClearCache() {
	m.localMu.Lock()
	defer m.localMu.Unlock()
	m.LocalCache = make(map[string]*tls.Certificate)
	m.logger.Info("TLS certificate cache cleared")
}

func (m *Manager) GetCertificateForPort(chi *tls.ClientHelloInfo, port string) (*tls.Certificate, error) {
	if chi.ServerName != "" {
		if cert, err := m.GetCertificate(chi); err == nil {
			return cert, nil
		}
	}

	hcfg := m.hostManager.GetByPort(port)
	if hcfg != nil && len(hcfg.Domains) > 0 {
		chi.ServerName = hcfg.Domains[0]
		return m.GetCertificate(chi)
	}

	return nil, woos.ErrCertNotfound
}
