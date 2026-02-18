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
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"git.imaxinacion.net/aibox/agbero/internal/core/zulu"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"github.com/caddyserver/certmagic"
	"github.com/fsnotify/fsnotify"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/mappo"
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

	initOnce sync.Once
	initErr  error

	// Session cache for TLS resumption (shared across all certs)
	sessionCache tls.ClientSessionCache

	// Config cache using your cache package
	configCache *mappo.Cache
}

func NewManager(logger *ll.Logger, hostManager *discovery.Host, global *alaye.Global) *Manager {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logger.Fatal(err)
	}
	m := &Manager{
		logger:       logger.Namespace("tlss"),
		hostManager:  hostManager,
		Global:       global,
		LocalCache:   make(map[string]*tls.Certificate),
		watchList:    make(map[string]func()),
		watcher:      watcher,
		sessionCache: tls.NewLRUClientSessionCache(10000),                   // 10k sessions
		configCache:  mappo.NewCache(mappo.CacheOptions{MaximumSize: 1000}), // 1000 host configs
	}

	go m.globalWatchLoop()
	return m
}

func (m *Manager) startLocalWatcher(cacheKey, certFile, keyFile, host string) {
	if m.watcher == nil {
		return
	}

	m.watcherMu.Lock()
	defer m.watcherMu.Unlock()

	if err := m.watcher.Add(certFile); err != nil {
		m.logger.Fields("file", certFile, "err", err).Error("failed to watch cert file")
	}
	if err := m.watcher.Add(keyFile); err != nil {
		m.logger.Fields("file", keyFile, "err", err).Error("failed to watch key file")
	}

	callback := func() { m.invalidateLocal(cacheKey, host) }
	m.watchList[certFile] = callback
	m.watchList[keyFile] = callback
}

func (m *Manager) globalWatchLoop() {
	if m.watcher == nil {
		return
	}
	for {
		select {
		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				m.watcherMu.Lock()
				if callback, exists := m.watchList[event.Name]; exists {
					go callback()
				}
				m.watcherMu.Unlock()
			}
		case <-m.watcher.Errors:
			return
		}
	}
}

func (m *Manager) initCertMagic() error {
	if m.Global == nil {
		return woos.ErrGlobalConfigRequired
	}

	if m.Global.LetsEncrypt.Enabled.NotActive() {
		return woos.ErrLetsEncryptNotEnabled
	}

	email := strings.TrimSpace(m.Global.LetsEncrypt.Email)
	if email == "" {
		return woos.ErrEmptyLEEmail
	}

	storageDir := strings.TrimSpace(m.Global.Storage.CertsDir)
	if storageDir == "" {
		return woos.ErrEmptyCertFile
	}
	storageDir = filepath.Clean(storageDir)

	decision := func(ctx context.Context, name string) error {
		return nil
	}

	cmProd := certmagic.NewDefault()
	cmProd.OnDemand = &certmagic.OnDemandConfig{DecisionFunc: decision}
	cmProd.Storage = &certmagic.FileStorage{Path: storageDir}
	acmeProd := certmagic.ACMEIssuer{
		Email:  email,
		Agreed: true,
		CA:     woos.LetsEncryptProdDir,
	}
	issuerProd := certmagic.NewACMEIssuer(cmProd, acmeProd)
	cmProd.Issuers = []certmagic.Issuer{issuerProd}
	cmProd.Logger = newTLSLogger(m.logger)

	m.cmProd = cmProd
	m.issProd = issuerProd

	cmStaging := certmagic.NewDefault()
	cmStaging.OnDemand = &certmagic.OnDemandConfig{DecisionFunc: decision}
	cmStaging.Storage = &certmagic.FileStorage{Path: storageDir}
	acmeStaging := certmagic.ACMEIssuer{
		Email:                   email,
		Agreed:                  true,
		CA:                      woos.LetsEncryptStagingDir,
		DisableTLSALPNChallenge: true,
	}
	issuerStaging := certmagic.NewACMEIssuer(cmStaging, acmeStaging)
	cmStaging.Issuers = []certmagic.Issuer{issuerStaging}
	cmStaging.Logger = newTLSLogger(m.logger)

	m.cmStaging = cmStaging
	m.issStaging = issuerStaging

	return nil
}

func (m *Manager) EnsureCertMagic(next http.Handler) (http.Handler, error) {
	m.initOnce.Do(func() {
		m.initErr = m.initCertMagic()
	})

	if m.initErr != nil {
		return next, m.initErr
	}

	h := next
	if m.Global.LetsEncrypt.Staging {
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
	if m.Global.LetsEncrypt.Enabled.NotActive() {
		return m.cmStaging
	}
	useStaging := m.Global.LetsEncrypt.Staging

	if hcfg.TLS.LetsEncrypt.Staging {
		useStaging = true
	}

	if useStaging {
		return m.cmStaging
	}
	return m.cmProd
}

func (m *Manager) GetCertificateLocal(local *alaye.LocalCert, host string) (*tls.Certificate, error) {
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

	m.startLocalWatcher(cacheKey, certFile, keyFile, host)
	return &cert, nil
}

func (m *Manager) GetCertificateAutoLocal(host string) (*tls.Certificate, error) {
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

func (m *Manager) GetCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if chi == nil || strings.TrimSpace(chi.ServerName) == "" {
		return nil, errors.New("missing SNI")
	}

	sni := zulu.NormalizeHost(chi.ServerName)
	if sni == "" {
		return nil, woos.ErrMissingSNI
	}

	if net.ParseIP(sni) != nil {
		return nil, woos.ErrMissingSNI
	}

	hcfg := m.hostManager.Get(sni)
	if hcfg == nil {
		return nil, errors.Newf("%w %q", woos.ErrUnknownHost, sni)
	}

	mode := alaye.TlsMode("")
	if hcfg.TLS.Mode != "" {
		mode = hcfg.TLS.Mode
	}

	if strings.TrimSpace(string(mode)) == "" {
		if woos.IsLocalhost(sni) {
			mode = alaye.ModeLocalAuto
		} else {
			mode = alaye.ModeLetsEncrypt
		}
	}

	switch mode {
	case alaye.ModeLocalNone:
		return nil, errors.Newf("%w: tls disabled for host %q", woos.ErrTLSDisabled, sni)

	case alaye.ModeLocalCert:
		if hcfg.TLS.Local.CertFile == "" || hcfg.TLS.Local.KeyFile == "" {
			return nil, errors.Newf("%w %q", woos.ErrLocalCertMissingFiles, sni)
		}
		return m.GetCertificateLocal(&hcfg.TLS.Local, sni)

	case alaye.ModeLocalAuto:
		if !woos.IsLocalhost(sni) {
			return nil, errors.Newf("%w (got %q)", woos.ErrLocalAutoNotAllowed, sni)
		}
		return m.GetCertificateAutoLocal(sni)

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
		if hcfg.TLS.CustomCA.Root == "" {
			return nil, errors.Newf("%w for host %q", woos.ErrCustomCAMissingRoot, sni)
		}
		return m.getCustomCACert(hcfg.TLS.CustomCA.Root, sni)

	default:
		return nil, errors.Newf("%w: %q for host %q", woos.ErrUnknownTLSMode, mode, sni)
	}
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

func (m *Manager) GetConfigForClient(chi *tls.ClientHelloInfo) (*tls.Config, error) {
	if chi == nil || strings.TrimSpace(chi.ServerName) == "" {
		return nil, errors.New("missing SNI")
	}

	sni := zulu.NormalizeHost(chi.ServerName)
	if sni == "" {
		return nil, woos.ErrMissingSNI
	}

	if cached, ok := m.configCache.Load(sni); ok {
		config, valid := zulu.GetCache[*tls.Config](cached)
		if valid && config != nil {
			if len(config.Certificates) > 0 {
				cert := config.Certificates[0]
				if len(cert.Certificate) > 0 {
					leaf, err := x509.ParseCertificate(cert.Certificate[0])
					if err == nil && time.Now().Before(leaf.NotAfter.Add(-5*time.Minute)) {
						newConfig := &tls.Config{
							Certificates:                []tls.Certificate{cert},
							ClientSessionCache:          config.ClientSessionCache,
							SessionTicketsDisabled:      config.SessionTicketsDisabled,
							CurvePreferences:            config.CurvePreferences,
							CipherSuites:                config.CipherSuites,
							MinVersion:                  config.MinVersion,
							MaxVersion:                  config.MaxVersion,
							DynamicRecordSizingDisabled: config.DynamicRecordSizingDisabled,
						}
						return newConfig, nil
					}
				}
			}
			m.configCache.Delete(sni)
		}
	}

	cert, err := m.GetCertificate(chi)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		Certificates:           []tls.Certificate{*cert},
		ClientSessionCache:     m.sessionCache,
		SessionTicketsDisabled: false,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		MinVersion:                  tls.VersionTLS12,
		DynamicRecordSizingDisabled: false,
	}

	m.configCache.Store(sni, &mappo.Item{
		Value: config,
	})

	return config, nil
}

func (m *Manager) invalidateLocal(cacheKey, host string) {
	m.localMu.Lock()
	delete(m.LocalCache, cacheKey)
	m.localMu.Unlock()

	// Also invalidate config cache since cert changed
	m.configCache.Delete(host)

	m.logger.Fields("host", host, "key", cacheKey).Info("local cert invalidated; will reload on next request")
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
		return m.GetCertificateLocal(&hcfg.TLS.Local, host)
	}
	return nil, errors.Newf("%w for host %q", woos.ErrUnknownHost, host)
}

func (m *Manager) Close() {
	m.watcherMu.Lock()
	defer m.watcherMu.Unlock()
	if m.watcher != nil {
		m.watcher.Close()
	}
}

func (m *Manager) ClearCache() {
	m.localMu.Lock()
	defer m.localMu.Unlock()
	m.LocalCache = make(map[string]*tls.Certificate)

	// Clear config cache too
	m.configCache = mappo.NewCache(mappo.CacheOptions{MaximumSize: 1000})

	m.logger.Info("TLS certificate cache cleared")
}
