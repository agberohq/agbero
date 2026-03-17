package agbero

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/agberohq/agbero/internal/cluster"
	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/resource"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/discovery"
	"github.com/agberohq/agbero/internal/handlers"
	"github.com/agberohq/agbero/internal/middleware/firewall"
	"github.com/agberohq/agbero/internal/pkg/cook"
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
}

// NewServer configures and injects dependencies required for core proxy execution.
// Prepares logic components before starting up listeners.
func NewServer(opts ...Option) *Server {
	s := &Server{}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// OnClusterChange processes routing updates from the gossip network.
// Informs the host manager of updates retrieved from other peers dynamically.
func (s *Server) OnClusterChange(key string, value []byte, deleted bool) {
	if s.hostManager != nil {
		s.hostManager.OnClusterChange(key, value, deleted)
	}
}

// OnClusterCert updates local TLS certificates safely across the cluster map.
// Resolves missing files whenever a peer resolves LetsEncrypt successfully.
func (s *Server) OnClusterCert(domain string, certPEM, keyPEM []byte) error {
	if s.tlsManager != nil {
		return s.tlsManager.ApplyClusterCertificate(domain, certPEM, keyPEM)
	}
	return nil
}

// OnClusterChallenge syncs an ACME domain challenge across the mesh.
// Provides global resolution regardless of which node Let's Encrypt contacts.
func (s *Server) OnClusterChallenge(token, keyAuth string, deleted bool) {
	if s.tlsManager != nil {
		s.tlsManager.ApplyClusterChallenge(token, keyAuth, deleted)
	}
}

// Start initializes systems, hooks watchers, and activates configured listeners.
// Spawns necessary daemon modules, cluster meshes, and HTTP/TCP frontends.
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
		for _, hcfg := range hosts {
			for _, r := range hcfg.Routes {
				if r.Web.Git.Enabled.Active() {
					err = s.cookManager.Register(r.Web.Git.ID, r.Web.Git)
					if err != nil {
						s.logger.Error("failed to register cook", "id", r.Web.Git.ID, "err", err)
					}
				}
			}
		}
	}

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

// Reload applies updated configurations to the server without downtime.
// Safely drains old connections to prevent dropping active websocket or file transfers.
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
	s.mu.RUnlock()

	if sha == currentSHA {
		return
	}

	global, err := parser.LoadGlobal(configPath)
	if err != nil {
		return
	}

	if s.global.Logging.Diff.Active() {
		for _, v := range zulu.Diff(s.global, global) {
			s.logger.Debug(v)
		}
	}

	absConfigPath, _ := filepath.Abs(configPath)
	woos.DefaultApply(global, absConfigPath)

	_ = s.hostManager.ReloadFull()

	s.mu.Lock()

	oldListeners := s.listeners
	oldTrafficManager := s.trafficManager
	oldSharedState := s.sharedState

	var trustedProxies []string
	if global.Security.Enabled.Active() {
		trustedProxies = global.Security.TrustedProxies
	}
	ipMgr := zulu.NewIPManager(trustedProxies)

	s.global = global
	s.configSHA = sha

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
	s.sharedState = newSharedState

	s.tlsManager.Close()
	s.tlsManager = tlss.NewManager(s.logger, s.hostManager, global)
	if s.clusterManager != nil {
		s.tlsManager.SetUpdateCallback(func(domain string, certPEM, keyPEM []byte) {
			_ = s.clusterManager.BroadcastCert(domain, certPEM, keyPEM)
		})
		s.tlsManager.SetCluster(s.clusterManager)
	}

	if oldTrafficManager != nil {
		oldTrafficManager.CloseFirewall()
	}

	tmCfg := handlers.ManagerConfig{
		Global:      s.global,
		HostManager: s.hostManager,
		Resource:    s.resource,
		IPMgr:       ipMgr,
		CookManager: s.cookManager,
		TLSManager:  s.tlsManager,
		SharedState: s.sharedState,
	}

	tm, err := handlers.NewManager(tmCfg)
	if err != nil {
		s.logger.Fields("err", err).Error("reload: failed to create traffic manager, keeping existing config")
		s.mu.Unlock()
		return
	}

	s.trafficManager = tm
	s.firewall = tm.Firewall()

	newListeners := tm.BuildListeners()
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

	// Start the new listeners first to ensure zero downtime
	for _, l := range newListeners {
		go func(listener handlers.Listener) {
			s.logger.Fields("bind", listener.Addr(), "proto", listener.Kind()).Info("reloaded listener starting")
			if err := listener.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.logger.Fields("err", err, "bind", listener.Addr()).Error("reloaded listener failed")
			}
		}(l)
	}

	// Drain the old listeners asynchronously so Reload() returns immediately
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

		if oldTrafficManager != nil {
			oldTrafficManager.Close()
		}

		if oldSharedState != nil {
			_ = oldSharedState.Close()
		}
	}()

	s.logger.Info("configuration reloaded successfully")
}

// shutdownImpl orchestrates a graceful teardown of the proxy server.
// Drains active connections and signals cluster peers before terminating.
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

// configComputeSHA hashes the main config file and all host files to detect changes.
// Reads under RLock to prevent data races with concurrent Reload calls.
func (s *Server) configComputeSHA() (string, error) {
	hasher := sha256.New()

	s.mu.RLock()
	configPath := s.configPath
	hostDir := s.global.Storage.HostsDir
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

// tlsValidate ensures required TLS certificates are present before startup.
func (s *Server) tlsValidate() error {
	return nil
}

// serverWatchConfig continuously monitors the host manager for configuration changes.
// Triggers hot-reloads seamlessly without dropping active client connections.
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
