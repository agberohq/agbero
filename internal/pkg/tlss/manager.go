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
}

// NewManager builds the cryptography orchestration layer.
// Links local CA issuing, Let's Encrypt automation, and secure cluster distribution.
func NewManager(logger *ll.Logger, hm *discovery.Host, global *alaye.Global) *Manager {
	m := &Manager{
		logger:         logger.Namespace("tls"),
		hostManager:    hm,
		global:         global,
		cache:          mappo.NewLRU[string, *tls.Certificate](10000),
		Challenges:     NewChallengeStore(logger),
		quit:           make(chan struct{}),
		pendingDomains: mappo.NewConcurrent[string, bool](),
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
// Uses a debouncer to gracefully combine matching key/cert file saves into one processing event.
func (m *Manager) scheduleCheck(domain string) {
	m.pendingDomains.Set(domain, true)
	m.debouncer.Do(m.processPending)
}

// processPending extracts all pending certificate files and initiates cluster distribution.
// It clears the concurrent map safely, avoiding processing the same domain multiple times.
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

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return
	}

	for _, ou := range leaf.Issuer.OrganizationalUnit {
		if strings.Contains(ou, "Development") {
			return
		}
	}

	if cached, hit := m.cache.Get(domain); hit {
		cachedLeaf, err := x509.ParseCertificate(cached.Certificate[0])
		if err == nil && cachedLeaf.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
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
func (m *Manager) GetCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := chi.ServerName
	if name == "" {
		return nil, woos.ErrMissingSNI
	}

	if cert, hit := m.cache.Get(name); hit {
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
				return &c, nil
			}
		}
		return nil, fmt.Errorf("failed to load manual certs for %s", name)
	case alaye.ModeLetsEncrypt:
		return m.getCertificateACME(name)
	}
	return nil, fmt.Errorf("no certificate strategy found for %s", name)
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

	m.cache.Set(host, &cert)
	return &cert, nil
}

func (m *Manager) getCertificateACME(domain string) (*tls.Certificate, error) {
	tlsCert, certPEM, keyPEM, err := m.acme.ObtainCert(domain)
	if err != nil {
		return nil, woos.ErrCertNotfound
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
