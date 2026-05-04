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
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/hub/discovery"
	"github.com/agberohq/agbero/internal/hub/tlss/tlsstore"
	"github.com/agberohq/agbero/internal/pkg/security"
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

type response struct {
	Domain string
	Error  error
}

type Manager struct {
	logger      *ll.Logger
	hostManager *discovery.Host
	global      *alaye.Global
	storage     tlsstore.Store
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
	localFlight     singleflight.Group

	closeOnce sync.Once
}

func NewManager(logger *ll.Logger, hm *discovery.Host, global *alaye.Global, keeperStore *keeper.Keeper) *Manager {
	m := &Manager{
		logger:          logger.Namespace("tlss"),
		hostManager:     hm,
		global:          global,
		cache:           mappo.NewLRU[string, *tls.Certificate](def.DefaultCacheMaxItems),
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
		ks, err := tlsstore.NewKeeper(keeperStore)
		if err == nil {
			m.storage = ks
			m.logger.Info("TLS storage initialized using Keeper backend")
		} else {
			m.logger.Fields("err", err).Warn("Failed to initialize Keeper TLS storage, falling back")
		}
	}

	dataDir := global.Storage.DataDir
	if m.storage == nil && dataDir.IsSet() {
		info, err := os.Stat(dataDir.Path())
		if err == nil && info.IsDir() {
			certDir := global.Storage.CertsDir
			if !filepath.IsAbs(certDir.String()) {
				certDir = expect.NewFolder(filepath.Join(dataDir.Path(), certDir.String()))
			}

			var cipher *security.Cipher
			if global.Gossip.Enabled.Active() && global.Gossip.SecretKey != "" {
				cipher, _ = security.NewCipher(global.Gossip.SecretKey.String())
			}

			diskCfg := tlsstore.DiskConfig{
				DataDir: dataDir,
				CertDir: certDir,
			}

			if cipher != nil {
				diskCfg.Cipher = cipher
			}

			ds, err := tlsstore.NewDisk(diskCfg)
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
		m.storage = tlsstore.NewMemory()
	}

	m.acme = NewACMEProvider(logger, m.storage, m.Challenges, global.LetsEncrypt)
	m.installer = NewLocal(logger, m.storage)

	m.loadFromStorage()

	if ds, isDisk := m.storage.(*tlsstore.Disk); isDisk {
		if err := m.startWatcher(ds.CertDir()); err != nil {
			m.logger.Fields("err", err).Warn("failed to start disk certificate watcher")
		}
	}

	return m
}

func (m *Manager) ListCertificates() ([]string, error) {
	if m.storage == nil {
		return nil, nil
	}
	return m.storage.List()
}

func (m *Manager) LoadCertificate(domain string) (certPEM, keyPEM []byte, err error) {
	if m.storage == nil {
		return nil, nil, tlsstore.ErrCertNotFound
	}
	return m.storage.Load(domain)
}

func (m *Manager) startWatcher(dir expect.Folder) error {
	if err := dir.Init(0755); err != nil {
		return err
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	m.watcher = watcher

	if err := m.watcher.Add(dir.Path()); err != nil {
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
		return nil, def.ErrMissingSNI
	}

	// Reject SNI values that are not valid hostnames before they reach any
	// storage or filesystem path.  A crafted SNI like
	// "../../etc/ld.so.preload.local" passes IsLocalhost (it ends in .local)
	// and then propagates into certPrefix / filepath.Join, writing files
	// anywhere on the filesystem.  RFC 1123 / RFC 5891 hostnames contain
	// only [a-zA-Z0-9\-.] and optionally a leading "*." for wildcards; reject
	// anything outside that set before the value touches any subsystem.
	if !isValidSNI(name) {
		return nil, def.ErrInvalidSNI
	}

	if cert, hit := m.cache.Get(name); hit {
		if m.needsRenewal(cert) {
			m.triggerRenewal(name, nil)
		}
		return cert, nil
	}

	host := m.hostManager.Get(name)
	mode := m.determineTLSMode(host, name)

	if host == nil && mode == def.ModeLocalNone {
		return nil, def.ErrCertNotfound
	}

	settings := m.global.LetsEncrypt
	if host != nil && host.TLS.LetsEncrypt.Enabled.Active() {
		settings = host.TLS.LetsEncrypt
	}

	switch mode {
	case def.ModeLocalAuto:
		return m.getCertificateLocal(name)

	case def.ModeLocalCert:
		if host != nil {
			if c, err := tls.LoadX509KeyPair(host.TLS.Local.CertFile, host.TLS.Local.KeyFile); err == nil {
				if len(c.Certificate) > 0 {
					c.Leaf, _ = x509.ParseCertificate(c.Certificate[0])
				}
				return &c, nil
			}
		}
		return nil, fmt.Errorf("failed to load manual certs for %s", name)

	case def.ModeLetsEncrypt:
		return m.getCertificateACME(name, settings)
	}

	return nil, def.ErrCertNotfound
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

	if totalLifetime < 24*time.Hour {
		return timeLeft < (totalLifetime / 3)
	}
	if totalLifetime > 89*24*time.Hour {
		return timeLeft < 30*24*time.Hour
	}
	return timeLeft < (totalLifetime / 3)
}

func (m *Manager) renewCertificateSync(domain string) error {
	host := m.hostManager.Get(domain)
	mode := m.determineTLSMode(host, domain)
	switch mode {
	case def.ModeLocalAuto:
		_, err := m.getCertificateLocal(domain)
		return err
	case def.ModeLetsEncrypt:
		if host == nil {
			return fmt.Errorf("host configuration not found for domain %s", domain)
		}
		_, err := m.getCertificateACME(domain, host.TLS.LetsEncrypt)
		return err
	default:
		return fmt.Errorf("renewal not supported for TLS mode %s", mode)
	}
}

func (m *Manager) triggerRenewal(domain string, onComplete func(response response)) {
	if _, loaded := m.renewingDomains.SetIfAbsent(domain, true); loaded {
		return
	}
	go func() {
		var err error
		defer m.renewingDomains.Delete(domain)
		if m.cluster != nil && !m.cluster.TryAcquireLock("renew:"+domain) {
			m.logger.Fields("domain", domain).Debug("cluster peer is already renewing certificate")
			return
		}
		m.logger.Fields("domain", domain).Info("certificate nearing expiration, starting background renewal")
		if err = m.renewCertificateSync(domain); err != nil {
			m.logger.Fields("domain", domain, "err", err).Error("failed to renew certificate")
		}
		if onComplete == nil {
			return
		}
		onComplete(response{Domain: domain, Error: err})
	}()
}

// getCertificateLocal generates or loads a local TLS certificate for host.
//
// localFlight collapses concurrent callers for the same domain into a single
// generation/load operation — identical to how acmeFlight protects ACME.
// Without this, simultaneous first-requests all miss the cache, race through
// EnsureForHost, and the ones that lose the storage write race return nil to
// the TLS layer, producing "no certificate found" handshake errors.
func (m *Manager) getCertificateLocal(host string) (*tls.Certificate, error) {
	v, err, _ := m.localFlight.Do(host, func() (any, error) {
		// storageKey is the normalised key EnsureForHost actually saved the cert
		// under (e.g. "admin" for host "admin.localhost").  It must be used for
		// the subsequent storage.Load — using the raw host would miss the cert.
		storageKey, _, err := m.installer.EnsureForHost(host, 443)
		if err != nil {
			return nil, err
		}

		certPEM, keyPEM, err := m.storage.Load(storageKey)
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

		if m.onUpdate != nil {
			go m.onUpdate(host, certPEM, keyPEM)
		}

		return &cert, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*tls.Certificate), nil
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

// PreloadLocalCertificates generates and caches TLS certificates for all hosts
// that use ModeLocalAuto before any listeners start.
//
// Calling this during server startup eliminates the first-request race
// condition where concurrent browser connections all find an empty cache,
// trigger parallel on-demand generation, and some receive nil mid-write.
// getCertificateLocal continues to use localFlight as a safety net for domains
// that are added dynamically after startup or that are not present at boot.
//
// Hosts whose certificate is already in the cache (loaded by loadFromStorage)
// are skipped — no duplicate work is done.
func (m *Manager) PreloadLocalCertificates(hosts map[string]*alaye.Host) {
	for domain, host := range hosts {
		if m.determineTLSMode(host, domain) != def.ModeLocalAuto {
			continue
		}
		// Already loaded from persistent storage by loadFromStorage — skip.
		if _, hit := m.cache.Get(domain); hit {
			m.logger.Fields("domain", domain).Debug("local cert already in cache, skipping preload")
			continue
		}
		m.logger.Fields("domain", domain).Debug("preloading local TLS certificate")
		if _, err := m.getCertificateLocal(domain); err != nil {
			// Non-fatal: log and continue.  The cert will be generated on
			// first request via the singleflight path.
			m.logger.Fields("domain", domain, "err", err).Warn("failed to preload local cert")
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
		case def.TlsRequireAndVerify:
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
		case def.TlsVerifyIfGiven:
			cfg.ClientAuth = tls.VerifyClientCertIfGiven
		case def.TlsRequire:
			cfg.ClientAuth = tls.RequireAnyClientCert
		case def.TlsRequest:
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
		if err := m.storage.Save(tlsstore.IssuerCustom, domain, certPEM, keyPEM); err != nil {
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
		if err := m.storage.Save(tlsstore.IssuerCustom, domain, certPEM, keyPEM); err != nil {
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

func (m *Manager) determineTLSMode(host *alaye.Host, domain string) def.TlsMode {
	if host == nil {
		return def.ModeLocalNone
	}

	if host.TLS.Mode != "" {
		return host.TLS.Mode
	}

	if host.TLS.Local.CertFile != "" && host.TLS.Local.KeyFile != "" {
		return def.ModeLocalCert
	}

	if host.TLS.LetsEncrypt.Enabled.Active() {
		return def.ModeLetsEncrypt
	}

	// no need to generate tls for internal names
	if strings.HasSuffix(strings.ToLower(domain), ".internal") {
		return def.ModeLocalNone
	}

	if woos.IsLocalhost(domain) {
		return def.ModeLocalAuto
	}

	if m.global.LetsEncrypt.Enabled.Active() {
		return def.ModeLetsEncrypt
	}

	return def.ModeLocalNone
}

// isValidSNI reports whether s is a syntactically valid TLS SNI hostname.
//
// RFC 5246 §7.4.1.2 specifies that the SNI name_type=host_name field MUST be
// a fully qualified DNS name.  RFC 1123 limits labels to [a-zA-Z0-9-] and
// dots as separators; RFC 5891 allows leading "*." for wildcard certificates.
// Anything outside this set — including path separators, ".." sequences, or
// null bytes — is illegal and must be rejected before the value reaches any
// filesystem or storage path.
func isValidSNI(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	// Wildcard prefix is allowed ("*.example.com") but only at the start.
	check := s
	if strings.HasPrefix(check, "*.") {
		check = check[2:]
	}
	// After stripping an optional wildcard prefix every character must be a
	// letter, digit, hyphen, or dot.  This explicitly blocks '/', '\\', and
	// ".." traversal sequences.
	for _, r := range check {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '.') {
			return false
		}
	}
	// Reject empty labels ("foo..bar") and leading/trailing dots.
	if strings.Contains(check, "..") || strings.HasPrefix(check, ".") || strings.HasSuffix(check, ".") {
		return false
	}
	return true
}
