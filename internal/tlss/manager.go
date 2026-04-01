package tlss

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/discovery"
	"github.com/agberohq/agbero/internal/pkg/security"
	tlsstore2 "github.com/agberohq/agbero/internal/tlss/tlsstore"
	"github.com/agberohq/keeper"
	"github.com/fsnotify/fsnotify"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/mappo"
	"golang.org/x/sync/singleflight"
)

type ClusterBroadcaster interface {
	BroadcastChallenge(token, keyAuth string, deleted bool)
	BroadcastCert(domain string, certPEM, keyPEM []byte) error
	TryAcquireLock(key string) bool
}

type Manager struct {
	logger      *ll.Logger
	hostManager *discovery.Host
	global      *alaye.Global
	storage     tlsstore2.Store
	installer   *Local
	acme        *ACMEProvider
	Challenges  *ChallengeStore
	cluster     ClusterBroadcaster
	cache       *mappo.LRU[string, *tls.Certificate]
	onUpdate    func(domain string, certPEM, keyPEM []byte)

	watcher        *fsnotify.Watcher
	quit           chan struct{}
	debouncer      *jack.Debouncer
	pendingDomains *mappo.Concurrent[string, bool]

	renewingDomains *mappo.Concurrent[string, bool]
	acmeFlight      singleflight.Group

	closeOnce sync.Once
}

func NewManager(logger *ll.Logger, hm *discovery.Host, global *alaye.Global, keeperStore *keeper.Keeper) *Manager {
	m := &Manager{
		logger:          logger.Namespace("tls"),
		hostManager:     hm,
		global:          global,
		cache:           mappo.NewLRU[string, *tls.Certificate](10000),
		Challenges:      NewChallengeStore(logger),
		quit:            make(chan struct{}),
		pendingDomains:  mappo.NewConcurrent[string, bool](),
		renewingDomains: mappo.NewConcurrent[string, bool](),
	}

	m.debouncer = jack.NewDebouncer(
		jack.WithDebounceDelay(500*time.Millisecond),
		jack.WithDebounceMaxWait(2*time.Second),
	)

	if keeperStore != nil && !keeperStore.IsLocked() {
		ks, err := tlsstore2.NewKeeper(keeperStore)
		if err == nil {
			m.storage = ks
			m.logger.Info("TLS storage initialized using Keeper backend")
		} else {
			m.logger.Fields("err", err).Warn("Failed to initialize Keeper TLS storage, falling back")
		}
	}

	dataDir := woos.NewFolder(global.Storage.DataDir)
	if m.storage == nil && dataDir.IsSet() {
		info, err := os.Stat(dataDir.Path())
		if err == nil && info.IsDir() {
			certDir := woos.NewFolder(global.Storage.CertsDir)
			if !filepath.IsAbs(certDir.String()) {
				certDir = woos.NewFolder(filepath.Join(dataDir.Path(), certDir.String()))
			}

			var cipher *security.Cipher
			if global.Gossip.Enabled.Active() && global.Gossip.SecretKey != "" {
				cipher, _ = security.NewCipher(global.Gossip.SecretKey.String())
			}

			diskCfg := tlsstore2.DiskConfig{
				DataDir: dataDir.Path(),
				CertDir: certDir.Path(),
			}

			if cipher != nil {
				diskCfg.Cipher = cipher
			}

			ds, err := tlsstore2.NewDisk(diskCfg)
			if err == nil {
				m.storage = ds
				m.logger.Info("TLS storage initialized using Disk backend")
			} else {
				m.logger.Fields("err", err).Warn("Failed to initialize Disk TLS storage, falling back")
			}
		}
	}

	if m.storage == nil {
		m.logger.Info("Persistent storage not configured or failed, running in ephemeral Memory mode")
		m.storage = tlsstore2.NewMemory()
	}

	m.acme = NewACMEProvider(logger, m.storage, m.Challenges, global.LetsEncrypt)
	m.installer = NewLocal(logger, m.storage)

	m.loadFromStorage()

	if ds, isDisk := m.storage.(*tlsstore2.Disk); isDisk {
		if err := m.startWatcher(ds.CertDir()); err != nil {
			m.logger.Fields("err", err).Warn("failed to start disk certificate watcher")
		}
	}

	return m
}

func (m *Manager) startWatcher(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	m.watcher = watcher

	if err := m.watcher.Add(dir); err != nil {
		m.watcher.Close()
		return err
	}

	go m.watchLoop()
	m.logger.Fields("dir", dir).Info("certificate directory watcher started")
	return nil
}

func (m *Manager) watchLoop() {
	for {
		select {
		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Chmod) {
				continue
			}

			name := filepath.Base(event.Name)
			if !strings.HasSuffix(name, ".crt") && !strings.HasSuffix(name, ".key") && !strings.HasSuffix(name, ".enc") {
				continue
			}

			domain := strings.TrimSuffix(name, ".crt")
			domain = strings.TrimSuffix(domain, ".key")
			domain = strings.TrimSuffix(domain, ".enc")
			domain = strings.ReplaceAll(domain, "_wildcard_", "*")

			m.scheduleCheck(domain)

		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			m.logger.Fields("err", err).Error("cert watcher error")
		case <-m.quit:
			return
		}
	}
}

func (m *Manager) scheduleCheck(domain string) {
	m.pendingDomains.Set(domain, true)
	m.debouncer.Do(m.processPending)
}

func (m *Manager) processPending() {
	var domains []string
	m.pendingDomains.Range(func(k string, v bool) bool {
		domains = append(domains, k)
		m.pendingDomains.Delete(k)
		return true
	})

	for _, domain := range domains {
		m.checkAndBroadcastCert(domain)
	}
}

func (m *Manager) checkAndBroadcastCert(domain string) {
	if domain == "ca-cert" || domain == "ca-key" || domain == "acme_account" {
		return
	}

	certPEM, keyPEM, err := m.storage.Load(domain)
	if err != nil {
		return
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return
	}

	if len(cert.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err == nil {
			cert.Leaf = leaf
			for _, ou := range leaf.Issuer.OrganizationalUnit {
				if strings.Contains(ou, "Development") {
					return
				}
			}
		}
	}

	if cached, hit := m.cache.Get(domain); hit && cached.Leaf != nil && cert.Leaf != nil {
		if cached.Leaf.SerialNumber.Cmp(cert.Leaf.SerialNumber) == 0 {
			return
		}
	}

	m.cache.Set(domain, &cert)

	if m.cluster != nil {
		if err := m.cluster.BroadcastCert(domain, certPEM, keyPEM); err != nil {
			m.logger.Fields("domain", domain, "err", err).Error("failed to broadcast certificate")
		} else {
			m.logger.Fields("domain", domain).Info("certificate broadcasted to cluster")
		}
	}
}

func (m *Manager) EnsureCertMagic(next http.Handler) (http.Handler, error) {
	return next, nil
}

func (m *Manager) GetCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := chi.ServerName
	if name == "" {
		return nil, woos.ErrMissingSNI
	}

	if cert, hit := m.cache.Get(name); hit {
		if m.needsRenewal(cert) {
			m.triggerRenewal(name)
		}
		return cert, nil
	}

	host := m.hostManager.Get(name)
	mode := m.determineTLSMode(host, name)

	// If no host and no default strategy, return ErrCertNotfound
	if host == nil && mode == alaye.ModeLocalNone {
		return nil, woos.ErrCertNotfound
	}

	settings := m.global.LetsEncrypt
	if host != nil && host.TLS.LetsEncrypt.Enabled.Active() {
		settings = host.TLS.LetsEncrypt
	}

	switch mode {
	case alaye.ModeLocalAuto:
		return m.getCertificateLocal(name)

	case alaye.ModeLocalCert:
		if host != nil {
			if c, err := tls.LoadX509KeyPair(host.TLS.Local.CertFile, host.TLS.Local.KeyFile); err == nil {
				if len(c.Certificate) > 0 {
					c.Leaf, _ = x509.ParseCertificate(c.Certificate[0])
				}
				return &c, nil
			}
		}
		return nil, fmt.Errorf("failed to load manual certs for %s", name)

	case alaye.ModeLetsEncrypt:
		return m.getCertificateACME(name, settings)
	}

	return nil, woos.ErrCertNotfound
}

func (m *Manager) needsRenewal(cert *tls.Certificate) bool {

	if cert.Leaf == nil {
		if len(cert.Certificate) > 0 {
			cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
		}
	}

	if cert.Leaf == nil {
		return false
	}

	now := time.Now()
	if now.After(cert.Leaf.NotAfter) {
		return true
	}

	timeLeft := cert.Leaf.NotAfter.Sub(now)
	totalLifetime := cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore)

	// For very short-lived certificates (like test certs), renew if less than 30% of lifetime remains
	if totalLifetime < 24*time.Hour {
		return timeLeft < (totalLifetime / 3)
	}

	// For Let's Encrypt certs (90 days), renew if less than 30 days remain
	if totalLifetime > 89*24*time.Hour {
		return timeLeft < 30*24*time.Hour
	}

	// Default: renew if less than 1/3 of lifetime remains
	return timeLeft < (totalLifetime / 3)
}

func (m *Manager) triggerRenewal(domain string) {
	if _, loaded := m.renewingDomains.SetIfAbsent(domain, true); loaded {
		return
	}

	go func() {
		defer m.renewingDomains.Delete(domain)

		if m.cluster != nil && !m.cluster.TryAcquireLock("renew:"+domain) {
			m.logger.Fields("domain", domain).Debug("cluster peer is already renewing certificate")
			return
		}

		m.logger.Fields("domain", domain).Info("certificate nearing expiration, starting background renewal")

		host := m.hostManager.Get(domain)
		mode := m.determineTLSMode(host, domain)

		switch mode {
		case alaye.ModeLocalAuto:
			if _, err := m.getCertificateLocal(domain); err != nil {
				m.logger.Fields("domain", domain, "err", err).Error("failed to renew local certificate")
			}
		case alaye.ModeLetsEncrypt:
			if _, err := m.getCertificateACME(domain, host.TLS.LetsEncrypt); err != nil {
				m.logger.Fields("domain", domain, "err", err).Error("failed to renew ACME certificate")
			}
		}
	}()
}

func (m *Manager) getCertificateLocal(host string) (*tls.Certificate, error) {
	_, _, err := m.installer.EnsureForHost(host, 443)
	if err != nil {
		return nil, err
	}

	certPEM, keyPEM, err := m.storage.Load(host)
	if err != nil {
		return nil, fmt.Errorf("failed to load local cert from store: %w", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	if len(cert.Certificate) > 0 {
		cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}

	m.cache.Set(host, &cert)
	return &cert, nil
}

func (m *Manager) getCertificateACME(domain string, setting alaye.LetsEncrypt) (*tls.Certificate, error) {
	v, err, _ := m.acmeFlight.Do(domain, func() (any, error) {
		tlsCert, certPEM, keyPEM, err := m.acme.ObtainCert(domain, setting)
		if err != nil {
			return nil, fmt.Errorf("acme failure: %w", err)
		}

		if len(tlsCert.Certificate) > 0 {
			tlsCert.Leaf, _ = x509.ParseCertificate(tlsCert.Certificate[0])
		}

		m.cache.Set(domain, tlsCert)

		if m.onUpdate != nil {
			go m.onUpdate(domain, certPEM, keyPEM)
		}
		return tlsCert, nil
	})

	if err != nil {
		return nil, err
	}
	return v.(*tls.Certificate), nil
}

func (m *Manager) loadFromStorage() {
	if m.storage == nil {
		return
	}
	list, _ := m.storage.List()
	for _, domain := range list {
		if domain == "acme_account" {
			continue
		}
		certPEM, keyPEM, err := m.storage.Load(domain)
		if err == nil {
			if cert, err := tls.X509KeyPair(certPEM, keyPEM); err == nil {
				if len(cert.Certificate) > 0 {
					cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
				}
				m.cache.Set(domain, &cert)
			}
		}
	}
}

func (m *Manager) GetConfigForClient(chi *tls.ClientHelloInfo) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if chi.ServerName == "" {
		return cfg, nil
	}

	host := m.hostManager.Get(chi.ServerName)
	if host != nil && host.TLS.ClientAuth != "" {
		switch strings.ToLower(host.TLS.ClientAuth) {
		case alaye.TlsRequireAndVerify:
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
		case alaye.TlsRequire:
			cfg.ClientAuth = tls.RequireAnyClientCert
		case alaye.TlsRequest:
			cfg.ClientAuth = tls.RequestClientCert
		default:
			cfg.ClientAuth = tls.NoClientCert
		}

		if len(host.TLS.ClientCAs) > 0 {
			pool := x509.NewCertPool()
			for _, path := range host.TLS.ClientCAs {
				if pem, err := os.ReadFile(path); err == nil {
					pool.AppendCertsFromPEM(pem)
				}
			}
			cfg.ClientCAs = pool
		}
	}
	return cfg, nil
}

func (m *Manager) Close() {
	m.closeOnce.Do(func() {
		if m.quit != nil {
			close(m.quit)
		}
		if m.watcher != nil {
			_ = m.watcher.Close()
		}
		if m.debouncer != nil {
			m.debouncer.Cancel()
		}
		m.cache.Clear()
		m.pendingDomains.Clear()
		m.renewingDomains.Clear()
	})
}

func (m *Manager) SetUpdateCallback(fn func(domain string, certPEM, keyPEM []byte)) {
	m.onUpdate = fn
}

func (m *Manager) SetCluster(c ClusterBroadcaster) {
	m.cluster = c
	m.Challenges.SetCluster(c)
}

func (m *Manager) ApplyClusterCertificate(domain string, certPEM, keyPEM []byte) error {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}

	if len(cert.Certificate) > 0 {
		cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}

	m.cache.Set(domain, &cert)

	if m.storage != nil {
		if err := m.storage.Save(tlsstore2.IssuerCustom, domain, certPEM, keyPEM); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) ApplyClusterChallenge(token, keyAuth string, deleted bool) {
	m.Challenges.SyncFromCluster(token, keyAuth, deleted)
}

func (m *Manager) UpdateCertificate(domain string, certPEM, keyPEM []byte) error {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}

	if len(cert.Certificate) > 0 {
		cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}

	m.cache.Set(domain, &cert)

	if m.storage != nil {
		if err := m.storage.Save(tlsstore2.IssuerCustom, domain, certPEM, keyPEM); err != nil {
			return err
		}
	}
	if m.onUpdate != nil {
		go m.onUpdate(domain, certPEM, keyPEM)
	}
	return nil
}

func (m *Manager) DeleteCertificate(domain string) error {
	if m.LikelyInternal(domain) {
		return fmt.Errorf("cannot delete internal certificate %s", domain)
	}

	m.cache.Delete(domain)

	if m.storage != nil {
		if err := m.storage.Delete(domain); err != nil {
			m.logger.Fields("domain", domain, "err", err).Warn("failed to delete cert from storage")
		}
	}

	m.logger.Fields("domain", domain).Info("certificate deleted from TLS manager")
	return nil
}

func (m *Manager) LikelyInternal(name string) bool {
	if strings.HasPrefix(name, "admin") || strings.HasPrefix(name, "ca") || strings.HasPrefix(name, "acme") {
		return true
	}
	return false
}

func (m *Manager) determineTLSMode(host *alaye.Host, domain string) alaye.TlsMode {
	if host == nil {
		return alaye.ModeLocalNone
	}

	if host.TLS.Mode != "" {
		return host.TLS.Mode
	}

	if host.TLS.Local.CertFile != "" && host.TLS.Local.KeyFile != "" {
		return alaye.ModeLocalCert
	}

	if host.TLS.LetsEncrypt.Enabled.Active() {
		return alaye.ModeLetsEncrypt
	}

	if woos.IsLocalhost(domain) {
		return alaye.ModeLocalAuto
	}

	if m.global.LetsEncrypt.Enabled.Active() {
		return alaye.ModeLetsEncrypt
	}

	return alaye.ModeLocalNone
}
