package tlss

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/discovery"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/olekukonko/ll"
)

type Manager struct {
	logger      *ll.Logger
	hostManager *discovery.Host
	global      *alaye.Global
	storage     Store
	installer   *Local
	acme        *ACMEProvider
	Challenges  *ChallengeStore
	cluster     ClusterBroadcaster
	cacheMu     sync.RWMutex
	cache       map[string]*tls.Certificate
	onUpdate    func(domain string, certPEM, keyPEM []byte)
}

func NewManager(logger *ll.Logger, hm *discovery.Host, global *alaye.Global) *Manager {
	m := &Manager{
		logger:      logger.Namespace("tls"),
		hostManager: hm,
		global:      global,
		cache:       make(map[string]*tls.Certificate),
		Challenges:  NewChallengeStore(logger),
	}
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
		m.storage = nil // <-- ADD THIS LINE
	}
	m.acme = NewACMEProvider(logger, &global.LetsEncrypt, m.storage, m.Challenges)
	certDir := woos.MakeFolder(global.Storage.CertsDir, woos.CertDir)
	m.installer = NewLocal(logger, certDir)
	m.loadFromStorage()
	return m
}

func (m *Manager) EnsureCertMagic(next http.Handler) (http.Handler, error) {
	return next, nil
}

func (m *Manager) GetCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := chi.ServerName
	if name == "" {
		return nil, woos.ErrMissingSNI
	}
	m.cacheMu.RLock()
	cert, hit := m.cache[name]
	m.cacheMu.RUnlock()
	if hit {
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
	m.cacheMu.Lock()
	m.cache[host] = &cert
	m.cacheMu.Unlock()
	return &cert, nil
}

func (m *Manager) getCertificateACME(domain string) (*tls.Certificate, error) {
	tlsCert, certPEM, keyPEM, err := m.acme.ObtainCert(domain)
	if err != nil {
		return nil, woos.ErrCertNotfound
	}
	m.cacheMu.Lock()
	m.cache[domain] = tlsCert
	m.cacheMu.Unlock()
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
				m.cacheMu.Lock()
				m.cache[domain] = &cert
				m.cacheMu.Unlock()
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

func (m *Manager) Close() {}

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
	m.cacheMu.Lock()
	m.cache[domain] = &cert
	m.cacheMu.Unlock()
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
	m.cacheMu.Lock()
	m.cache[domain] = &cert
	m.cacheMu.Unlock()
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
