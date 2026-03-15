package tlss

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/discovery"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/fsnotify/fsnotify"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/mappo"
)

// ClusterBroadcaster defines requirements for distributing PKI material.
type ClusterBroadcaster interface {
	BroadcastChallenge(token, keyAuth string, deleted bool)
	BroadcastCert(domain string, certPEM, keyPEM []byte) error
	TryAcquireLock(key string) bool
}

type Manager struct {
	logger      *ll.Logger
	hostManager *discovery.Host
	global      *alaye.Global
	storage     Store
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

	// Tracks domains currently being renewed to prevent thundering herd
	renewingDomains *mappo.Concurrent[string, bool]
}

// NewManager builds the cryptography orchestration layer.
// Links local CA issuing, Let's Encrypt automation, and secure cluster distribution.
func NewManager(logger *ll.Logger, hm *discovery.Host, global *alaye.Global) *Manager {
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

	baseDir := woos.MakeFolder(global.Storage.DataDir, woos.DataDir)

	var cipher *security.Cipher
	if global.Gossip.Enabled.Active() && global.Gossip.SecretKey != "" {
		var err error
		cipher, err = security.NewCipher(string(global.Gossip.SecretKey))
		if err != nil {
			m.logger.Warn("invalid gossip secret key, storage will be plaintext")
		}
	}

	var err error
	m.storage, err = NewDiskStorage(baseDir, cipher)
	if err != nil {
		m.logger.Error("failed to initialize TLS storage", "error", err)
		m.storage = nil
	}

	m.acme = NewACMEProvider(logger, &global.LetsEncrypt, m.storage, m.Challenges)
	certDir := woos.MakeFolder(global.Storage.CertsDir, woos.CertDir)
	m.installer = NewLocal(logger, certDir)

	m.loadFromStorage()

	if err := m.startWatcher(certDir.Path()); err != nil {
		m.logger.Fields("err", err).Warn("failed to start certificate watcher")
	}

	return m
}

// startWatcher initializes the filesystem observer for custom certificates.
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

// watchLoop parses incoming events, capturing drops of external wildcard or standard certs.
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

// scheduleCheck queues a domain for certificate parsing and broadcast.
func (m *Manager) scheduleCheck(domain string) {
	m.pendingDomains.Set(domain, true)
	m.debouncer.Do(m.processPending)
}

// processPending extracts all pending certificate files and initiates cluster distribution.
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

// checkAndBroadcastCert validates manually placed certificates, ignores local CAs, and delegates to the cluster.
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
					return // Ignore mkcert/local dev certs
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

// GetCertificate evaluates the request SNI and supplies the correct TLS material.
// Performs O(1) zero-allocation expiration checks to trigger background renewals.
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
	mode := alaye.ModeLetsEncrypt
	if host != nil && host.TLS.Mode != "" {
		mode = host.TLS.Mode
	} else if woos.IsLocalhost(name) {
		mode = alaye.ModeLocalAuto
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
		return m.getCertificateACME(name)
	}

	return nil, fmt.Errorf("no certificate strategy found for %s", name)
}

// needsRenewal determines if a certificate is approaching expiration.
// Supports standard 90-day Let's Encrypt and short-lived Pebble certificates.
func (m *Manager) needsRenewal(cert *tls.Certificate) bool {
	if cert.Leaf == nil {
		if len(cert.Certificate) > 0 {
			cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
		}
	}

	if cert.Leaf == nil {
		return false // Unable to parse, do not infinitely retry
	}

	now := time.Now()
	if now.After(cert.Leaf.NotAfter) {
		return true // Expired
	}

	timeLeft := cert.Leaf.NotAfter.Sub(now)
	totalLifetime := cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore)

	// Standard Let's Encrypt (90 days) - renew at 30 days remaining
	if totalLifetime > 89*24*time.Hour {
		return timeLeft < 30*24*time.Hour
	}

	// Short-lived certs (e.g. Pebble) - renew at 1/3 lifetime remaining
	return timeLeft < (totalLifetime / 3)
}

// triggerRenewal spawns a background worker to fetch a new certificate.
// Safely dedupes local concurrent requests and utilizes cluster locks.
func (m *Manager) triggerRenewal(domain string) {
	if _, exists := m.renewingDomains.Get(domain); exists {
		return
	}

	m.renewingDomains.Set(domain, true)

	go func() {
		defer m.renewingDomains.Delete(domain)

		// Prevent multiple nodes from hammering Let's Encrypt simultaneously
		if m.cluster != nil && !m.cluster.TryAcquireLock("renew:"+domain) {
			m.logger.Fields("domain", domain).Debug("cluster peer is already renewing certificate")
			return
		}

		m.logger.Fields("domain", domain).Info("certificate nearing expiration, starting background renewal")

		host := m.hostManager.Get(domain)
		mode := alaye.ModeLetsEncrypt
		if host != nil && host.TLS.Mode != "" {
			mode = host.TLS.Mode
		} else if woos.IsLocalhost(domain) {
			mode = alaye.ModeLocalAuto
		}

		switch mode {
		case alaye.ModeLocalAuto:
			if _, err := m.getCertificateLocal(domain); err != nil {
				m.logger.Fields("domain", domain, "err", err).Error("failed to renew local certificate")
			}
		case alaye.ModeLetsEncrypt:
			if _, err := m.getCertificateACME(domain); err != nil {
				m.logger.Fields("domain", domain, "err", err).Error("failed to renew ACME certificate")
			}
		}
	}()
}

func (m *Manager) getCertificateLocal(host string) (*tls.Certificate, error) {
	m.installer.SetHosts([]string{host}, 443)
	certFile, keyFile, err := m.installer.EnsureLocalhostCert()
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	if len(cert.Certificate) > 0 {
		cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}

	m.cache.Set(host, &cert)
	return &cert, nil
}

func (m *Manager) getCertificateACME(domain string) (*tls.Certificate, error) {
	tlsCert, certPEM, keyPEM, err := m.acme.ObtainCert(domain)
	if err != nil {
		return nil, woos.ErrCertNotfound
	}

	if len(tlsCert.Certificate) > 0 {
		tlsCert.Leaf, _ = x509.ParseCertificate(tlsCert.Certificate[0])
	}

	m.cache.Set(domain, tlsCert)

	if m.storage != nil {
		m.storage.Save(domain, certPEM, keyPEM)
	}
	if m.onUpdate != nil {
		go m.onUpdate(domain, certPEM, keyPEM)
	}
	return tlsCert, nil
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
		m.storage.Save(domain, certPEM, keyPEM)
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
		if err := m.storage.Save(domain, certPEM, keyPEM); err != nil {
			return err
		}
	}
	if m.onUpdate != nil {
		go m.onUpdate(domain, certPEM, keyPEM)
	}
	return nil
}
