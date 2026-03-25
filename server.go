// Package agbero provides the main server implementation and lifecycle management.
// It coordinates listeners, security managers, and traffic managers for proxy operations.
package agbero

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/agberohq/agbero/internal/cluster"
	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/resource"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/discovery"
	"github.com/agberohq/agbero/internal/handlers"
	"github.com/agberohq/agbero/internal/middleware/firewall"
	"github.com/agberohq/agbero/internal/pkg/cook"
	"github.com/agberohq/agbero/internal/pkg/orchestrator"
	"github.com/agberohq/agbero/internal/pkg/parser"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/agberohq/agbero/internal/pkg/telemetry"
	"github.com/agberohq/agbero/internal/pkg/tlss"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/mappo"
)

const (
	defaultReloadTimeout   = woos.DefaultReloadTimeout
	defaultShutdownTimeout = woos.DefaultShutdownTimeout
	defaultGitPoolTimeout  = woos.DefaultGitPoolTimeout
	defaultGitPoolSize     = woos.DefaultGitPoolSize
)

type Server struct {
	configPath string
	configSHA  string

	hostManager     *discovery.Host
	global          *alaye.Global
	tlsManager      *tlss.Manager
	securityManager *security.Manager
	resource        *resource.Resource
	orchManager     *orchestrator.Manager

	mu        sync.RWMutex
	listeners []handlers.Listener

	logger *ll.Logger

	clusterManager *cluster.Manager
	gitPool        *jack.Pool
	cookManager    *cook.Manager
	trafficManager *handlers.Manager

	shutdown *jack.Shutdown

	firewall    *firewall.Engine
	sharedState woos.SharedState

	telemetryStore     *telemetry.Store
	telemetryCollector *telemetry.Collector

	// adminSrv and pprofSrv are stored so they can be gracefully shut down
	// via s.shutdown on process exit rather than being hard-killed.
	adminSrv *http.Server
	pprofSrv *http.Server

	// jtiStore holds revoked admin JWT identifiers mapped to their expiry time.
	// mappo.Concurrent is used for its lock-free read performance under high concurrency.
	jtiStore *mappo.Concurrent[string, time.Time]

	// jtiLifetime schedules automatic removal of expired JTI entries so the
	// revocation map does not accumulate stale entries indefinitely.
	jtiLifetime *jack.Lifetime
}

// NewServer initializes a Server instance with the provided options.
// It configures the core components before the start sequence is initiated.
func NewServer(opts ...Option) *Server {
	s := &Server{
		jtiStore:    mappo.NewConcurrent[string, time.Time](),
		jtiLifetime: jack.NewLifetime(jack.LifetimeWithShards(woos.LifetimeShards)),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// OnClusterChange implements the cluster update handler for route modifications.
// It signals the host manager to update internal routing tables based on peer updates.
func (s *Server) OnClusterChange(key string, value []byte, deleted bool) {
	if s.hostManager != nil {
		s.hostManager.OnClusterChange(key, value, deleted)
	}
}

// OnClusterCert handles the synchronization of certificates across the cluster.
// It ensures that ACME certificates obtained by one node are available to all peers.
func (s *Server) OnClusterCert(domain string, certPEM, keyPEM []byte) error {
	if s.tlsManager != nil {
		return s.tlsManager.ApplyClusterCertificate(domain, certPEM, keyPEM)
	}
	return nil
}

// OnClusterChallenge synchronizes ACME challenge tokens across cluster members.
// It allows any node to fulfill a challenge request regardless of which node initiated it.
func (s *Server) OnClusterChallenge(token, keyAuth string, deleted bool) {
	if s.tlsManager != nil {
		s.tlsManager.ApplyClusterChallenge(token, keyAuth, deleted)
	}
}

// Start - boots up the server instance and all background dependencies
// Initializes orchestrator, cache, clustering, and local listeners
func (s *Server) Start(configPath string) error {
	s.mu.Lock()
	s.configPath = configPath
	s.mu.Unlock()

	if s.hostManager == nil {
		return woos.ErrHostManagerRequired
	}
	if s.global == nil {
		return woos.ErrGlobalConfigRequired
	}
	if s.logger == nil {
		s.logger = ll.New(woos.Name).Enable()
	}

	if configPath != "" {
		absConfigPath, err := filepath.Abs(configPath)
		if err != nil {
			absConfigPath = configPath
		}
		woos.DefaultApply(s.global, absConfigPath)
		if sha, err := s.configComputeSHA(); err == nil {
			s.configSHA = sha
			s.logger.Fields("config_path", absConfigPath, "sha256", sha[:12]).Infof("config loaded")
		}
	} else {
		woos.DefaultApply(s.global, ".")
		s.logger.Info("starting in ephemeral mode")
	}

	if s.resource == nil {
		s.resource = resource.New(
			resource.WithLogger(s.logger),
			resource.WithShutdown(s.shutdown),
			resource.WithReaper(func(ctx context.Context, id string) {
				if s.resource != nil {
					if it, ok := s.resource.RouteCache.Load(id); ok {
						if h, ok := it.Value.(*handlers.Route); ok {
							h.Close()
						}
					}
					s.resource.RouteCache.Delete(id)
				}
			}))
	}

	s.populateResourceEnv()

	if s.shutdown != nil {
		s.shutdown.RegisterFunc("Resource", s.resource.Close)
	}

	if s.global.Security.Enabled.Active() && s.global.Security.InternalAuthKey != "" {
		mgr, err := security.LoadKeys(s.global.Security.InternalAuthKey)
		if err != nil {
			return err
		}
		s.securityManager = mgr
	}

	if err := s.tlsValidate(); err != nil {
		return err
	}

	if configPath != "" {
		if err := s.hostManager.ReloadFull(); err != nil {
			return err
		}
	}

	hosts, _ := s.hostManager.LoadAll()

	s.gitPool = jack.NewPool(defaultGitPoolSize)
	cookCfg := cook.ManagerConfig{
		WorkDir: s.global.Storage.WorkDir,
		Pool:    s.gitPool,
		Logger:  s.logger,
	}

	cookMgr, err := cook.NewManager(cookCfg)
	if err == nil {
		s.cookManager = cookMgr
		seenGitConfigs := make(map[string]alaye.Git)
		for _, hcfg := range hosts {
			for _, r := range hcfg.Routes {
				if r.Web.Git.Enabled.Active() {
					gitID := r.Web.Git.ID
					if existing, exists := seenGitConfigs[gitID]; exists {
						if existing.URL != r.Web.Git.URL || existing.Branch != r.Web.Git.Branch || existing.WorkDir != r.Web.Git.WorkDir {
							s.logger.Fields("id", gitID).Warn("server: Git ID collision with differing configurations detected, skipping duplicate")
						}
						continue
					}
					seenGitConfigs[gitID] = r.Web.Git
					err = s.cookManager.Register(gitID, r.Web.Git)
					if err != nil {
						s.logger.Error("failed to register cook", "id", gitID, "err", err)
					}
				}
			}
		}
	}

	s.orchManager = orchestrator.New(s.logger, s.global.Storage.WorkDir, s.cookManager, s.global.Env)

	if s.global.Gossip.SharedState.Enabled.Active() {
		if s.global.Gossip.SharedState.Driver == "redis" {
			ss, err := cluster.NewRedisSharedState(s.global.Gossip.SharedState.Redis)
			if err != nil {
				s.logger.Error("failed to initialize redis shared state", "err", err)
			} else {
				s.sharedState = ss
				if s.shutdown != nil {
					s.shutdown.RegisterFunc("SharedState", func() { _ = ss.Close() })
				}
				s.logger.Info("redis shared state initialized for cluster")
			}
		}
	}

	if s.global.Gossip.Enabled.Active() {
		cfg := cluster.Config{
			Name:     s.global.Admin.Address,
			BindPort: s.global.Gossip.Port,
			Secret:   []byte(s.global.Gossip.SecretKey),
			Seeds:    s.global.Gossip.Seeds,
			HostsDir: s.global.Storage.HostsDir,
		}
		if cfg.Name == "" || strings.HasPrefix(cfg.Name, ":") {
			hostname, _ := os.Hostname()
			cfg.Name = fmt.Sprintf("agbero-%s-%d", hostname, s.global.Gossip.Port)
		}
		if cm, err := cluster.NewManager(cfg, s, s.logger); err == nil {
			s.clusterManager = cm
			if s.shutdown != nil {
				s.shutdown.RegisterFunc("Cluster", func() { _ = s.clusterManager.Shutdown() })
			}
		}
	}

	if s.global.Storage.DataDir != "" {
		ts, err := telemetry.NewStore(s.global.Storage.DataDir)
		if err != nil {
			s.logger.Fields("err", err).Warn("telemetry store unavailable, history disabled")
		} else {
			s.telemetryStore = ts
			col := telemetry.NewCollector(ts, s.hostManager, s.resource, s.logger)
			col.Start()
			s.telemetryCollector = col
			if s.shutdown != nil {
				s.shutdown.RegisterFunc("Telemetry", func() {
					col.Stop()
					_ = ts.Close()
				})
			}
		}
	}

	s.startAdminServer()
	s.startPprofServer()

	s.tlsManager = tlss.NewManager(s.logger, s.hostManager, s.global)
	if s.shutdown != nil {
		s.shutdown.RegisterFunc("TLSManager", s.tlsManager.Close)
	}
	if s.clusterManager != nil {
		s.tlsManager.SetUpdateCallback(func(domain string, certPEM, keyPEM []byte) {
			_ = s.clusterManager.BroadcastCert(domain, certPEM, keyPEM)
		})
		s.tlsManager.SetCluster(s.clusterManager)
	}

	var trustedProxies []string
	if s.global.Security.Enabled.Active() {
		trustedProxies = s.global.Security.TrustedProxies
	}
	ipMgr := zulu.NewIPManager(trustedProxies)

	tmCfg := handlers.ManagerConfig{
		Global:      s.global,
		HostManager: s.hostManager,
		Resource:    s.resource,
		IPMgr:       ipMgr,
		CookManager: s.cookManager,
		TLSManager:  s.tlsManager,
		SharedState: s.sharedState,
		OrchManager: s.orchManager,
	}

	tm, err := handlers.NewManager(tmCfg)
	if err != nil {
		return errors.Newf("traffic manager init: %w", err)
	}
	s.trafficManager = tm
	s.firewall = tm.Firewall()

	if s.shutdown != nil {
		s.shutdown.RegisterFunc("TrafficManager", tm.Close)
	}

	listeners := tm.BuildListeners()
	s.mu.Lock()
	s.listeners = listeners
	s.mu.Unlock()

	if len(listeners) == 0 {
		return woos.ErrNoBindAddr
	}

	for _, l := range listeners {
		go func(listener handlers.Listener) {
			s.logger.Fields("bind", listener.Addr(), "proto", listener.Kind()).Info("listener starting")
			if err := listener.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.logger.Fields("err", err, "bind", listener.Addr()).Error("listener failed")
			}
		}(l)
	}

	if configPath != "" {
		go s.serverWatchConfig()
	}

	if s.shutdown != nil {
		s.shutdown.RegisterWithContext("Listeners", s.shutdownImpl)
	}

	<-s.shutdown.Done()
	return nil
}

// Reload applies an updated configuration without dropping active connections.
// It builds new listeners and traffic managers before tearing down the old ones.
func (s *Server) Reload() {
	s.mu.RLock()
	configPath := s.configPath
	s.mu.RUnlock()

	if configPath == "" {
		return
	}

	sha, err := s.configComputeSHA()
	if err != nil {
		return
	}

	s.mu.RLock()
	currentSHA := s.configSHA
	currentGlobal := s.global
	s.mu.RUnlock()

	if sha == currentSHA {
		return
	}

	global, err := parser.LoadGlobal(configPath)
	if err != nil {
		return
	}

	if currentGlobal.Logging.Diff.Active() {
		for _, v := range zulu.Diff(currentGlobal, global) {
			s.logger.Debug(v)
		}
	}

	absConfigPath, _ := filepath.Abs(configPath)
	woos.DefaultApply(global, absConfigPath)

	_ = s.hostManager.ReloadFull()

	var newSharedState woos.SharedState
	if global.Gossip.SharedState.Enabled.Active() && global.Gossip.SharedState.Driver == "redis" {
		ss, err := cluster.NewRedisSharedState(global.Gossip.SharedState.Redis)
		if err == nil {
			newSharedState = ss
			s.logger.Info("redis shared state reloaded")
		} else {
			s.logger.Error("failed to reload redis shared state", "err", err)
		}
	}

	var trustedProxies []string
	if global.Security.Enabled.Active() {
		trustedProxies = global.Security.TrustedProxies
	}
	ipMgr := zulu.NewIPManager(trustedProxies)

	newTLSManager := tlss.NewManager(s.logger, s.hostManager, global)
	if s.clusterManager != nil {
		newTLSManager.SetUpdateCallback(func(domain string, certPEM, keyPEM []byte) {
			_ = s.clusterManager.BroadcastCert(domain, certPEM, keyPEM)
		})
		newTLSManager.SetCluster(s.clusterManager)
	}

	tmCfg := handlers.ManagerConfig{
		Global:      global,
		HostManager: s.hostManager,
		Resource:    s.resource,
		IPMgr:       ipMgr,
		CookManager: s.cookManager,
		TLSManager:  newTLSManager,
		SharedState: newSharedState,
		OrchManager: s.orchManager,
	}

	s.mu.RLock()
	oldTrafficManagerForFirewall := s.trafficManager
	s.mu.RUnlock()

	if oldTrafficManagerForFirewall != nil {
		oldTrafficManagerForFirewall.CloseFirewall()
	}

	newTM, err := handlers.NewManager(tmCfg)
	if err != nil {
		s.logger.Fields("err", err).Error("reload: failed to create traffic manager, keeping existing config")
		if newSharedState != nil {
			_ = newSharedState.Close()
		}
		newTLSManager.Close()
		return
	}

	newListeners := newTM.BuildListeners()

	s.mu.Lock()
	oldListeners := s.listeners
	oldTrafficManager := s.trafficManager
	oldSharedState := s.sharedState
	oldTLSManager := s.tlsManager

	s.global = global
	s.configSHA = sha
	s.sharedState = newSharedState

	s.populateResourceEnv()

	s.tlsManager = newTLSManager

	s.trafficManager = newTM
	s.firewall = newTM.Firewall()
	s.listeners = newListeners
	s.mu.Unlock()

	hosts, _ := s.hostManager.LoadAll()
	validKeys := make(map[alaye.BackendKey]bool)
	validRouteKeys := make(map[string]bool)

	for domain, h := range hosts {
		for _, r := range h.Routes {
			validRouteKeys[r.Key()] = true
			if r.Backends.Enabled.Active() {
				for _, srv := range r.Backends.Servers {
					validKeys[r.BackendKey(domain, srv.Address.String())] = true
				}
			}
		}
		for _, proxy := range h.Proxies {
			for _, srv := range proxy.Backends {
				validKeys[proxy.BackendKey(srv.Address.String())] = true
			}
		}
	}

	s.resource.Metrics.Prune(validKeys)

	if s.cookManager != nil {
		validGitIDs := make(map[string]bool)
		seenGitConfigs := make(map[string]alaye.Git)
		for _, hcfg := range hosts {
			for _, r := range hcfg.Routes {
				if r.Web.Git.Enabled.Active() {
					gitID := r.Web.Git.ID
					validGitIDs[gitID] = true
					if existing, exists := seenGitConfigs[gitID]; exists {
						if existing.URL != r.Web.Git.URL || existing.Branch != r.Web.Git.Branch || existing.WorkDir != r.Web.Git.WorkDir {
							s.logger.Fields("id", gitID).Warn("server: Git ID collision with differing configurations detected, skipping duplicate")
						}
						continue
					}
					seenGitConfigs[gitID] = r.Web.Git
					if err := s.cookManager.Register(gitID, r.Web.Git); err != nil {
						s.logger.Error("failed to register/update cook", "id", gitID, "err", err)
					}
				}
			}
		}
		s.cookManager.Prune(validGitIDs)
	}

	var staleRoutes []string
	s.resource.RouteCache.Range(func(k string, it *mappo.Item) bool {
		if !validRouteKeys[k] {
			staleRoutes = append(staleRoutes, k)
		}
		return true
	})
	for _, k := range staleRoutes {
		s.resource.RouteCache.Delete(k)
		if s.resource.Reaper != nil {
			s.resource.Reaper.Remove(k)
		}
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), defaultReloadTimeout)
		defer cancel()

		var wg sync.WaitGroup
		for _, l := range oldListeners {
			wg.Add(1)
			go func(oldListener handlers.Listener) {
				defer wg.Done()
				_ = oldListener.Stop(ctx)
			}(l)
		}
		wg.Wait()

		oldTLSManager.Close()

		if oldTrafficManager != nil {
			oldTrafficManager.Close()
		}

		if oldSharedState != nil {
			_ = oldSharedState.Close()
		}
	}()

	for _, l := range newListeners {
		go func(listener handlers.Listener) {
			s.logger.Fields("bind", listener.Addr(), "proto", listener.Kind()).Info("reloaded listener")
			var err error
			for i := 0; i < woos.MaxPortRetries; i++ {
				err = listener.Start()
				if err != nil {
					errStr := err.Error()
					if strings.Contains(errStr, "address already in use") || strings.Contains(errStr, "Only one usage") {
						if i < woos.MaxPortRetries-1 {
							time.Sleep(100 * time.Millisecond)
							continue
						}
					}
					if !errors.Is(err, http.ErrServerClosed) {
						s.logger.Fields("err", err, "bind", listener.Addr()).Error("reloaded listener failed")
					}
				}
				break
			}
		}(l)
	}

	s.logger.Info("configuration reloaded successfully")
}

// shutdownImpl performs the final listener termination during server shutdown.
// It ensures all active connections are drained or timed out before process exit.
func (s *Server) shutdownImpl(ctx context.Context) error {
	if s.clusterManager != nil {
		s.clusterManager.BroadcastStatus("draining")
	}
	if s.cookManager != nil {
		s.cookManager.Stop()
	}
	if s.gitPool != nil {
		_ = s.gitPool.Shutdown(defaultGitPoolTimeout)
	}
	if s.jtiLifetime != nil {
		s.jtiLifetime.Stop()
	}

	s.mu.RLock()
	listeners := s.listeners
	s.mu.RUnlock()

	var wg sync.WaitGroup
	for _, l := range listeners {
		wg.Add(1)
		go func(listener handlers.Listener) {
			defer wg.Done()
			_ = listener.Stop(ctx)
		}(l)
	}
	wg.Wait()
	return nil
}

// configComputeSHA calculates the SHA-256 fingerprint of the main config and host directory.
// It is used to detect filesystem changes that trigger a hot reload.
func (s *Server) configComputeSHA() (string, error) {
	hasher := sha256.New()

	s.mu.RLock()
	configPath := s.configPath
	var hostDir string
	if s.global != nil {
		hostDir = s.global.Storage.HostsDir
	}
	s.mu.RUnlock()

	mainData, err := os.ReadFile(configPath)
	if err != nil {
		return "", err
	}
	hasher.Write(mainData)

	entries, err := os.ReadDir(hostDir)
	if err != nil {
		return hex.EncodeToString(hasher.Sum(nil)), nil
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	for _, name := range files {
		path := filepath.Join(hostDir, name)
		data, _ := os.ReadFile(path)
		hasher.Write([]byte(name))
		hasher.Write(data)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// tlsValidate checks that every host configured with a local certificate can
// load its key pair before the server binds any listeners.
func (s *Server) tlsValidate() error {
	hosts, _ := s.hostManager.LoadAll()
	for domain, h := range hosts {
		if h.TLS.Mode == alaye.ModeLocalCert && h.TLS.Local.Enabled.Active() {
			if _, err := tls.LoadX509KeyPair(h.TLS.Local.CertFile, h.TLS.Local.KeyFile); err != nil {
				return fmt.Errorf("tls: host %q: %w", domain, err)
			}
		}
	}
	return nil
}

// serverWatchConfig monitors the host manager for change events that require a reload.
// It executes a full reload sequence whenever configuration updates are detected.
func (s *Server) serverWatchConfig() {
	for {
		select {
		case <-s.hostManager.Changed():
			s.Reload()
		case <-s.shutdown.Done():
			return
		}
	}
}

// populateResourceEnv copies global environment variables into the resource manager.
// It performs an atomic pointer swap so concurrent readers never see a partially populated map.
func (s *Server) populateResourceEnv() {
	if s.resource == nil || s.resource.Env == nil {
		return
	}
	newGlobal := mappo.NewConcurrent[string, alaye.Value]()
	for k, v := range s.global.Env {
		newGlobal.Set(k, v)
	}
	s.resource.Env.Global = newGlobal
}
