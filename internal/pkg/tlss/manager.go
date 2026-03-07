package tlss

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"git.imaxinacion.net/aibox/agbero/internal/core/zulu"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
)

const (
	renewalWindow = 30 * 24 * time.Hour // 30 days
	checkInterval = 1 * time.Hour
)

type CertCache map[string]*tls.Certificate

type OnUpdateFunc func(domain string, certPEM, keyPEM []byte)

// ClusterInterface defines what TLS manager needs from the cluster
type ClusterInterface interface {
	TryAcquireLock(key string) bool
	BroadcastChallenge(token, keyAuth string, deleted bool)
}

type Manager struct {
	logger      *ll.Logger
	hostManager *discovery.Host
	global      *alaye.Global

	storage     Storage
	activeCerts atomic.Value
	onUpdate    OnUpdateFunc
	scheduler   *jack.Scheduler
	cluster     ClusterInterface

	Challenges *ChallengeStore

	mu sync.Mutex
}

func NewManager(logger *ll.Logger, hm *discovery.Host, global *alaye.Global) *Manager {
	m := &Manager{
		logger:      logger.Namespace("tls"),
		hostManager: hm,
		global:      global,
		Challenges:  NewChallengeStore(logger),
	}

	m.activeCerts.Store(&CertCache{})

	secret := global.Gossip.SecretKey.String()
	store, err := NewDiskStorage(woos.NewFolder(global.Storage.CertsDir), secret)
	if err != nil {
		m.logger.Fields("err", err).Error("failed to init disk storage")
	} else {
		m.storage = store
		if err := m.loadFromStorage(); err != nil {
			m.logger.Fields("err", err).Warn("failed to load initial certificates")
		}
	}

	m.startScheduler()
	return m
}

func (m *Manager) SetUpdateCallback(fn OnUpdateFunc) {
	m.onUpdate = fn
}

func (m *Manager) SetCluster(c ClusterInterface) {
	m.cluster = c
	// Wire the ChallengeStore to the Cluster for broadcasting
	m.Challenges.SetCluster(c)
}

func (m *Manager) Close() {
	if m.scheduler != nil {
		_ = m.scheduler.Stop()
	}
}

func (m *Manager) GetConfigForClient(chi *tls.ClientHelloInfo) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	return cfg, nil
}

func (m *Manager) GetCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := zulu.NormalizeSubject(chi.ServerName)
	if name == "" {
		return nil, woos.ErrMissingSNI
	}

	cache := *m.activeCerts.Load().(*CertCache)

	if cert, ok := cache[name]; ok {
		return cert, nil
	}

	if idx := strings.Index(name, "."); idx != -1 {
		wildcard := "*" + name[idx:]
		if cert, ok := cache[wildcard]; ok {
			return cert, nil
		}
	}

	return nil, woos.ErrCertNotfound
}

func (m *Manager) UpdateCertificate(domain string, certPEM, keyPEM []byte) error {
	return m.updateInternal(domain, certPEM, keyPEM, true)
}

func (m *Manager) ApplyClusterCertificate(domain string, certPEM, keyPEM []byte) error {
	return m.updateInternal(domain, certPEM, keyPEM, false)
}

// ApplyClusterChallenge is called by the Server when gossip receives a challenge update
func (m *Manager) ApplyClusterChallenge(token, keyAuth string, deleted bool) {
	m.Challenges.SyncFromCluster(token, keyAuth, deleted)
}

func (m *Manager) updateInternal(domain string, certPEM, keyPEM []byte, notify bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	domain = zulu.NormalizeSubject(domain)

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}

	if len(tlsCert.Certificate) > 0 {
		tlsCert.Leaf, _ = x509.ParseCertificate(tlsCert.Certificate[0])
	}

	if m.storage != nil {
		if err := m.storage.Save(domain, certPEM, keyPEM); err != nil {
			return err
		}
	}

	current := m.activeCerts.Load().(*CertCache)
	newCache := make(CertCache, len(*current)+1)
	for k, v := range *current {
		newCache[k] = v
	}
	newCache[domain] = &tlsCert

	m.activeCerts.Store(&newCache)
	m.logger.Fields("domain", domain).Info("certificate updated")

	if notify && m.onUpdate != nil {
		go m.onUpdate(domain, certPEM, keyPEM)
	}

	return nil
}

func (m *Manager) loadFromStorage() error {
	if m.storage == nil {
		return nil
	}

	domains, err := m.storage.List()
	if err != nil {
		return err
	}

	newCache := make(CertCache)
	count := 0

	for _, domain := range domains {
		certPEM, keyPEM, err := m.storage.Load(domain)
		if err != nil {
			continue
		}

		tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			continue
		}

		if len(tlsCert.Certificate) > 0 {
			tlsCert.Leaf, _ = x509.ParseCertificate(tlsCert.Certificate[0])
		}

		newCache[domain] = &tlsCert
		count++
	}

	m.activeCerts.Store(&newCache)
	return nil
}

func (m *Manager) startScheduler() {
	sched, _ := jack.NewScheduler("tls-renewal", jack.NewPool(1), jack.Routine{
		Interval: checkInterval,
	})
	_ = sched.Do(jack.Do(m.checkRenewals))
	m.scheduler = sched
}

func (m *Manager) obtainCert(domain string) {
	m.logger.Fields("domain", domain).Info("starting acme renewal")

	client, err := m.setupLegoClient()
	if err != nil {
		m.logger.Fields("domain", domain, "err", err).Error("failed to setup acme client")
		return
	}

	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		m.logger.Fields("domain", domain, "err", err).Error("acme obtain failed")
		return
	}

	// Success! Update local and broadcast.
	err = m.UpdateCertificate(domain, certificates.Certificate, certificates.PrivateKey)
	if err != nil {
		m.logger.Fields("domain", domain, "err", err).Error("failed to save obtained certificate")
	} else {
		m.logger.Fields("domain", domain).Info("certificate renewed successfully")
	}
}

func (m *Manager) checkRenewals() {
	cache := *m.activeCerts.Load().(*CertCache)
	now := time.Now()

	for domain, cert := range cache {
		if cert.Leaf == nil {
			continue
		}

		remaining := cert.Leaf.NotAfter.Sub(now)

		// If < 30 days
		if remaining < renewalWindow {

			// Distributed Lock Check
			if m.cluster != nil {
				if !m.cluster.TryAcquireLock("renew:" + domain) {
					m.logger.Fields("domain", domain).Debug("skipping renewal, locked by another node")
					continue
				}
			}

			m.logger.Fields("domain", domain, "remaining", remaining).Info("acquired lock, triggering renewal")

			// Execute renewal in background so loop continues
			go m.obtainCert(domain)
		}
	}
}

func (m *Manager) EnsureCertMagic(next http.Handler) (http.Handler, error) {
	return next, nil
}
