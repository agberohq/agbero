package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agberohq/agbero/internal/cluster"
	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/pkg/matcher"
	"github.com/agberohq/agbero/internal/pkg/parser"
	"github.com/fsnotify/fsnotify"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
)

const ClusterRoutePrefix = "route:"

const (
	configSyncNamespace = "config_sync"
	debounceDelay       = 500 * time.Millisecond
	debounceMaxWait     = 2 * time.Second
	notifyChanBuffer    = 1
	zeroValue           = 0
	emptyString         = ""
)

type routeWrapper struct {
	Route     alaye.Route `json:"route"`
	ExpiresAt time.Time   `json:"expires_at"`
}

type Host struct {
	hostsDir woos.Folder

	mu            sync.RWMutex
	hosts         map[string]*alaye.Host
	clusterRoutes map[string]alaye.Route

	lookupMap  atomic.Value
	portLookup atomic.Value
	routers    atomic.Value

	watcher *fsnotify.Watcher
	logger  *ll.Logger
	changed chan struct{}

	debouncer *jack.Debouncer
	lifetimes *jack.Lifetime
	loaded    bool

	configSync *ConfigSync
	clusterMgr *cluster.Manager
}

type ConfigSync struct {
	logger  *ll.Logger
	cluster *cluster.Manager
}

// NewConfigSync initializes the bridge between discovery and cluster configurations.
// It relies completely on the cluster's Distributor for state tracking.
func NewConfigSync(logger *ll.Logger, cluster *cluster.Manager) *ConfigSync {
	return &ConfigSync{
		logger:  logger.Namespace(configSyncNamespace),
		cluster: cluster,
	}
}

// ShouldBroadcast delegates checksum validation to the central cluster manager.
// It prevents fsnotify echo loops by ensuring only genuinely new files trigger broadcasts.
func (c *ConfigSync) ShouldBroadcast(domain string, content []byte) bool {
	if c.cluster == nil || c.cluster.ConfigManager() == nil {
		return false
	}
	return c.cluster.ConfigManager().ShouldBroadcast(domain, content)
}

// ShouldBroadcastDeletion delegates deletion validation to the central cluster manager.
// It verifies if the file was previously known before broadcasting its removal.
func (c *ConfigSync) ShouldBroadcastDeletion(domain string) bool {
	if c.cluster == nil || c.cluster.ConfigManager() == nil {
		return false
	}
	return c.cluster.ConfigManager().ShouldBroadcastDeletion(domain)
}

// NewHost allocates a new Host discovery engine and prepares caching structures.
// It initializes debouncers and lock-free router maps for instantaneous traffic updates.
func NewHost(hostsDir woos.Folder, opts ...Option) *Host {
	h := &Host{
		hostsDir:      hostsDir,
		hosts:         make(map[string]*alaye.Host),
		clusterRoutes: make(map[string]alaye.Route),
		changed:       make(chan struct{}, notifyChanBuffer),
		loaded:        false,
	}
	for _, opt := range opts {
		opt(h)
	}
	if h.logger == nil {
		h.logger = ll.New(woos.Name).Disable()
	}

	h.lifetimes = jack.NewLifetime(
		jack.LifetimeWithLogger(h.logger),
		jack.LifetimeWithShards(woos.LifetimeShards),
	)

	h.lookupMap.Store(make(map[string]*alaye.Host))
	h.portLookup.Store(make(map[string]*alaye.Host))
	h.routers.Store(make(map[string]*matcher.Tree))

	h.debouncer = jack.NewDebouncer(
		jack.WithDebounceDelay(debounceDelay),
		jack.WithDebounceMaxWait(debounceMaxWait),
	)

	return h
}

// OnClusterCert handles certificate updates from the cluster.
// Domain is validated to prevent path traversal before writing any file.
func (hm *Host) OnClusterCert(domain string, certPEM, keyPEM []byte) error {
	if err := validatePathSegment(domain); err != nil {
		return fmt.Errorf("cluster cert rejected: %w", err)
	}

	certDir := filepath.Join(hm.hostsDir.Path(), "..", "certs")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("create certs dir: %w", err)
	}

	certTmp := filepath.Join(certDir, domain+".crt.tmp")
	keyTmp := filepath.Join(certDir, domain+".key.tmp")
	certPath := filepath.Join(certDir, domain+".crt")
	keyPath := filepath.Join(certDir, domain+".key")

	if err := os.WriteFile(certTmp, certPEM, 0644); err != nil {
		return fmt.Errorf("write cert tmp: %w", err)
	}
	if err := os.WriteFile(keyTmp, keyPEM, 0600); err != nil {
		_ = os.Remove(certTmp)
		return fmt.Errorf("write key tmp: %w", err)
	}
	if err := os.Rename(certTmp, certPath); err != nil {
		_ = os.Remove(certTmp)
		_ = os.Remove(keyTmp)
		return fmt.Errorf("rename cert: %w", err)
	}
	if err := os.Rename(keyTmp, keyPath); err != nil {
		_ = os.Remove(keyTmp)
		return fmt.Errorf("rename key: %w", err)
	}

	hm.logger.Fields("domain", domain).Info("cluster certificate applied")
	return nil
}

// OnClusterChallenge handles ACME challenge updates from the cluster.
// Token is validated against RFC 8555 format before any file operation.
func (hm *Host) OnClusterChallenge(token, keyAuth string, deleted bool) {
	if err := validateACMEToken(token); err != nil {
		hm.logger.Fields("token", token, "err", err).Error("cluster challenge rejected: invalid token")
		return
	}

	challengeDir := filepath.Join(hm.hostsDir.Path(), ".well-known", "acme-challenge")

	if deleted {
		_ = os.Remove(filepath.Join(challengeDir, token))
		hm.logger.Fields("token", token).Debug("cluster challenge removed")
		return
	}

	if err := os.MkdirAll(challengeDir, 0755); err != nil {
		hm.logger.Fields("token", token, "err", err).Error("failed to create challenge dir")
		return
	}

	challengePath := filepath.Join(challengeDir, token)
	if err := os.WriteFile(challengePath, []byte(keyAuth), 0644); err != nil {
		hm.logger.Fields("token", token, "err", err).Error("failed to write cluster challenge")
		return
	}

	hm.logger.Fields("token", token).Debug("cluster challenge applied")
}

// OnClusterChange processes incoming routing updates from the gossip network.
// Segregates cluster-specific routes and signals the router to rebuild.
func (hm *Host) OnClusterChange(key string, value []byte, deleted bool) {
	if !strings.HasPrefix(key, ClusterRoutePrefix) {
		return
	}

	trimmedKey := strings.TrimPrefix(key, ClusterRoutePrefix)

	if deleted {
		hm.handleRouteDeletion(trimmedKey)
	} else {
		hm.handleRouteUpdate(key, trimmedKey, value)
	}
}

// handleRouteDeletion removes an ephemeral route and triggers a routing rebuild.
// Clears associated lifetime schedules to prevent memory leaks.
func (hm *Host) handleRouteDeletion(key string) {
	hm.mu.Lock()
	delete(hm.clusterRoutes, key)
	hm.mu.Unlock()

	hm.lifetimes.CancelTimed(key)

	hm.logger.Fields("key", key).Info("cluster route removed")
	hm.debouncer.Do(hm.rebuildAndNotify)
}

// handleRouteUpdate merges an incoming cluster route into local memory.
// Establishes a TTL schedule if the route configuration defines an expiration time.
func (hm *Host) handleRouteUpdate(originalKey, trimmedKey string, value []byte) {
	var wrapper routeWrapper
	if err := json.Unmarshal(value, &wrapper); err != nil {
		var simpleRoute alaye.Route
		if err2 := json.Unmarshal(value, &simpleRoute); err2 == nil {
			wrapper.Route = simpleRoute
			wrapper.ExpiresAt = time.Time{}
		} else {
			hm.logger.Fields("key", originalKey, "err", err).Error("failed to unmarshal cluster route")
			return
		}
	}

	if !wrapper.ExpiresAt.IsZero() {
		timeLeft := time.Until(wrapper.ExpiresAt)
		if timeLeft <= zeroValue {
			hm.handleRouteDeletion(trimmedKey)
			return
		}

		hm.lifetimes.ScheduleTimed(context.Background(), trimmedKey, func(ctx context.Context, id string) {
			hm.logger.Fields("key", id).Info("route expired via lifetime")
			hm.handleRouteDeletion(id)
		}, timeLeft)
	} else {
		hm.lifetimes.CancelTimed(trimmedKey)
	}

	woos.DefaultRoute(&wrapper.Route)

	hm.mu.Lock()
	hm.clusterRoutes[trimmedKey] = wrapper.Route
	hm.mu.Unlock()

	hm.logger.Fields("key", trimmedKey).Debug("cluster route updated")
	hm.debouncer.Do(hm.rebuildAndNotify)
}

// LoadStatic injects predefined configurations directly into memory.
// Utilized heavily in ephemeral modes where disk persistence isn't required.
func (hm *Host) LoadStatic(staticHosts map[string]*alaye.Host) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	for _, h := range staticHosts {
		woos.DefaultHost(h)
		hm.sortRoutes(h.Routes)
	}

	hm.hosts = staticHosts
	hm.rebuildLookupLocked()
	hm.loaded = true

	hm.logger.Fields("count", len(staticHosts)).Info("static hosts loaded from memory")
}

// rebuildAndNotify computes lock-free lookup maps and dispatches an update signal.
// Allows the core server to transition active configurations without dropping traffic.
func (hm *Host) rebuildAndNotify() {
	hm.mu.Lock()
	hm.rebuildLookupLocked()
	hm.mu.Unlock()
	hm.logger.Info("router rebuilt from updates")
	hm.notifyChanged()
}

// RouteExists checks if a specific path is mapped under the given hostname.
// Exclusively queries the active lock-free map to avoid bottlenecking.
func (hm *Host) RouteExists(host, path string) bool {
	host, path = normalizeHostPath(host, path)
	if host == emptyString {
		return false
	}

	m := hm.lookupMap.Load().(map[string]*alaye.Host)
	cfg, ok := m[host]
	if !ok || cfg == nil {
		return false
	}
	for _, r := range cfg.Routes {
		p := r.Path
		if p == emptyString {
			p = woos.Slash
		}
		if p == path {
			return true
		}
	}
	return false
}

// Watch initializes the file system observer over the hosts directory.
// Establishes recursive monitoring to capture sub-directory changes immediately.
func (hm *Host) Watch() error {
	var err error
	hm.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	if err := hm.loadInternal(); err != nil {
		_ = hm.watcher.Close()
		return err
	}

	if hm.hostsDirExists() {
		if err := hm.addWatchRecursive(hm.hostsDir.Path()); err != nil {
			_ = hm.watcher.Close()
			return err
		}
		go hm.watchLoop()
		hm.logger.Fields("dir", hm.hostsDir).Info("host discovery watching")
	} else {
		hm.logger.Fields("dir", hm.hostsDir).Error("hosts directory does not exist, skipping watch")
	}

	return nil
}

// addWatchRecursive registers all subdirectories for fsnotify events.
// Crucial for recognizing nested host configuration topologies.
func (hm *Host) addWatchRecursive(root string) error {
	return filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		return hm.watcher.Add(p)
	})
}

// watchLoop continuously intercepts fsnotify events until shutdown.
// Filters out noise and executes debounced reloads on legitimate changes.
func (hm *Host) watchLoop() {
	debouncedReload := zulu.Debounce(debounceDelay, func() {
		_ = hm.ReloadFull()
	})

	for {
		select {
		case event, ok := <-hm.watcher.Events:
			if !ok {
				return
			}
			hm.handleEvent(event, debouncedReload)

		case err, ok := <-hm.watcher.Errors:
			if !ok {
				return
			}
			hm.logger.Fields("err", err.Error()).Error("watcher error")
		}
	}
}

// handleEvent processes filesystem notifications and triggers reloads.
// It intercepts file creations, modifications, and deletions to synchronize state across the cluster.
func (hm *Host) handleEvent(event fsnotify.Event, debouncedReload func()) {
	if event.Has(fsnotify.Chmod) {
		return
	}

	if event.Has(fsnotify.Create) {
		if fi, err := os.Stat(event.Name); err == nil && fi.IsDir() {
			_ = hm.addWatchRecursive(event.Name)
			return
		}
	}

	name := strings.ToLower(event.Name)
	if !strings.HasSuffix(name, woos.HCLSuffix) {
		return
	}

	if hm.clusterMgr != nil {
		domain := strings.TrimSuffix(filepath.Base(event.Name), woos.HCLSuffix)

		isRemove := event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename)
		isWrite := event.Has(fsnotify.Write) || event.Has(fsnotify.Create)

		if isRemove {
			if hm.configSync.ShouldBroadcastDeletion(domain) {
				go hm.clusterMgr.BroadcastConfig(domain, nil, true)
			}
		} else if isWrite {
			content, err := os.ReadFile(event.Name)
			if err == nil {
				if hm.configSync.ShouldBroadcast(domain, content) {
					go hm.clusterMgr.BroadcastConfig(domain, content, false)
				}
			}
		}
	}

	hm.logger.Fields(
		"event", event.Op.String(),
		"file", filepath.Base(event.Name),
	).Debug("config change detected, scheduling reload")

	debouncedReload()
}

// ReloadFull forcibly clears the active lookup maps and scans the disk anew.
// Triggers the changed channel to notify core processing modules.
func (hm *Host) ReloadFull() error {
	if err := hm.loadInternal(); err != nil {
		return err
	}
	hm.notifyChanged()
	return nil
}

// loadInternal safely swaps out the configuration states from scanned files.
// Protects the underlying mappings with a brief write lock.
func (hm *Host) loadInternal() error {
	newHosts, stats, err := hm.scanFromDisk()
	if err != nil {
		hm.logger.Fields("err", err).Error("failed to scan hosts from disk")
		return err
	}

	hm.mu.Lock()
	defer hm.mu.Unlock()

	hm.hosts = newHosts
	hm.loaded = true
	hm.rebuildLookupLocked()

	hm.logger.Fields(
		"total_files", stats.TotalFiles,
		"valid_hosts", len(newHosts),
	).Info("host configuration loaded")

	return nil
}

// scanFromDisk parses all valid HCL configuration files in the directory tree.
// Filters broken definitions and returns the verified mappings.
func (hm *Host) scanFromDisk() (map[string]*alaye.Host, struct{ TotalFiles int }, error) {
	out := make(map[string]*alaye.Host)
	stats := struct{ TotalFiles int }{}

	if !hm.hostsDirExists() {
		return out, stats, nil
	}

	root := hm.hostsDir.Path()
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}

		name := d.Name()
		if !strings.HasSuffix(strings.ToLower(name), woos.HCLSuffix) {
			return nil
		}

		stats.TotalFiles++

		cfg, err := hm.loadOne(p)
		if err != nil {
			hm.logger.Fields("file", name, "err", err).Error("failed to parse host config")
			return nil
		}

		if len(cfg.Domains) == zeroValue {
			hm.logger.Fields("file", name).Warn("host file has no domains, ignoring")
			return nil
		}

		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			rel = p
		}
		hostID := strings.TrimSuffix(rel, woos.HCLSuffix)
		hostID = strings.ReplaceAll(hostID, string(filepath.Separator), woos.Slash)

		out[hostID] = cfg
		return nil
	})

	return out, stats, err
}

// Get queries the active lock-free map for a specific host configuration.
// Utilizes prefix matching to securely resolve wildcard configurations.
func (hm *Host) Get(hostname string) *alaye.Host {
	hostname = zulu.NormalizeHost(hostname)
	if hostname == emptyString {
		return nil
	}

	m := hm.lookupMap.Load().(map[string]*alaye.Host)
	key := hm.resolveDomain(m, hostname)
	if key == emptyString {
		return nil
	}
	return m[key]
}

// GetRouter returns the compiled fast-matching radix tree for the given host.
// Rejects unknown domains without establishing an expensive lock attempt.
func (hm *Host) GetRouter(hostname string) *matcher.Tree {
	hostname = zulu.NormalizeHost(hostname)
	if hostname == emptyString {
		return nil
	}

	m := hm.lookupMap.Load().(map[string]*alaye.Host)
	key := hm.resolveDomain(m, hostname)
	if key == emptyString {
		return nil
	}

	r := hm.routers.Load().(map[string]*matcher.Tree)
	return r[key]
}

// GetByPort searches the configuration explicitly for binding targets.
// Utilized when standard domain resolution falls back to port-based binding.
func (hm *Host) GetByPort(port string) *alaye.Host {
	m := hm.portLookup.Load().(map[string]*alaye.Host)
	return m[port]
}

// LoadAll returns a safe snapshot of the entire host configuration map.
// Copies pointers to prevent external mutation of internal maps.
func (hm *Host) LoadAll() (map[string]*alaye.Host, error) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	if !hm.loaded {
		nh, _, err := hm.scanFromDisk()
		if err != nil {
			return nil, err
		}
		hm.hosts = nh
		hm.rebuildLookupLocked()
		hm.loaded = true
	}

	m := hm.lookupMap.Load().(map[string]*alaye.Host)
	out := make(map[string]*alaye.Host, len(m))
	maps.Copy(out, m)
	return out, nil
}

// Close gracefully ceases file watching operations and background debouncers.
// Must be called on application shutdown to prevent routine leaks.
func (hm *Host) Close() error {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	if hm.lifetimes != nil {
		hm.lifetimes.Stop()
	}

	if hm.debouncer != nil {
		hm.debouncer.Cancel()
	}

	if hm.watcher != nil {
		return hm.watcher.Close()
	}
	return nil
}

// Changed provides a read-only channel to observe reload events.
// The core server listens to this channel to trigger global reloads.
func (hm *Host) Changed() <-chan struct{} {
	return hm.changed
}

// notifyChanged signals the system that internal routing maps have transformed.
// Drops consecutive triggers if the channel buffer is already saturated.
func (hm *Host) notifyChanged() {
	select {
	case hm.changed <- struct{}{}:
	default:
	}
}

// rebuildLookupLocked constructs flattened routing structures for lightning-fast lookups.
// Instantiates precompiled matchers and isolates cluster routes organically.
func (hm *Host) rebuildLookupLocked() {
	newLookup := make(map[string]*alaye.Host)
	newPortLookup := make(map[string]*alaye.Host)
	domainToConfig := make(map[string]*alaye.Host)
	domainToRoutes := make(map[string][]alaye.Route)

	for _, cfg := range hm.hosts {
		for _, port := range cfg.Bind {
			newPortLookup[port] = cfg
		}
		for _, domain := range cfg.Domains {
			domain = strings.ToLower(strings.TrimSpace(domain))
			if domain == emptyString {
				continue
			}
			if _, exists := domainToConfig[domain]; !exists {
				domainToConfig[domain] = cfg
			}
			domainToRoutes[domain] = append(domainToRoutes[domain], cfg.Routes...)
		}
	}

	for key, route := range hm.clusterRoutes {
		parts := strings.SplitN(key, "|", 2)
		host := parts[zeroValue]

		if len(parts) > 1 && route.Path == emptyString {
			route.Path = parts[1]
		}
		if route.Path == emptyString {
			route.Path = woos.Slash
		}

		domainToRoutes[host] = append(domainToRoutes[host], route)

		if _, exists := domainToConfig[host]; !exists {
			defaultHost := &alaye.Host{
				Domains: []string{host},
				TLS:     alaye.TLS{Mode: alaye.ModeLocalAuto},
			}

			// If it's a public domain, default to Let's Encrypt instead of mkcert
			if !woos.IsLocalContext(host) {
				defaultHost.TLS.Mode = alaye.ModeLetsEncrypt
			}
			woos.DefaultHost(defaultHost)
			domainToConfig[host] = defaultHost
		}
	}

	for domain, baseCfg := range domainToConfig {
		combined := *baseCfg
		combined.Domains = []string{domain}

		rts := domainToRoutes[domain]
		combined.Routes = make([]alaye.Route, len(rts))
		copy(combined.Routes, rts)

		hm.sortRoutes(combined.Routes)
		newLookup[domain] = &combined
	}

	newRouters := make(map[string]*matcher.Tree, len(newLookup))
	for domain, cfg := range newLookup {
		tr := matcher.NewTree()
		for i := range cfg.Routes {
			_ = tr.Insert(cfg.Routes[i].Path, &cfg.Routes[i])
		}
		newRouters[domain] = tr
	}

	hm.lookupMap.Store(newLookup)
	hm.portLookup.Store(newPortLookup)
	hm.routers.Store(newRouters)
}

// loadOne extracts structure definitions directly from raw HCL representations.
// Performs default value injection immediately post-parsing.
func (hm *Host) loadOne(path string) (*alaye.Host, error) {
	var hostConfig alaye.Host
	parser := parser.NewParser(path)
	if err := parser.Unmarshal(&hostConfig); err != nil {
		return nil, err
	}

	woos.DefaultHost(&hostConfig)

	hm.sortRoutes(hostConfig.Routes)
	return &hostConfig, nil
}

// hostsDirExists asserts the validity of the fundamental discovery path.
// Prevents panic states during recursive tree traversals.
func (hm *Host) hostsDirExists() bool {
	p := hm.hostsDir.Path()
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// sortRoutes re-orders pathways from longest to shortest.
// Ensures specific paths take precedence over generalized matching logic.
func (hm *Host) sortRoutes(routes []alaye.Route) {
	sort.SliceStable(routes, func(i, j int) bool {
		return len(routes[i].Path) > len(routes[j].Path)
	})
}

// resolveDomain matches an exact domain or falls back to wildcard expressions.
// Assures requests are directed accurately within complex wildcard domains.
func (hm *Host) resolveDomain(lookup map[string]*alaye.Host, hostname string) string {
	if _, ok := lookup[hostname]; ok {
		return hostname
	}

	var bestMatch string
	var maxLen int

	for domain := range lookup {
		if strings.HasPrefix(domain, "*.") {
			suffix := domain[1:]
			if strings.HasSuffix(hostname, suffix) {
				if len(suffix) > maxLen {
					maxLen = len(suffix)
					bestMatch = domain
				}
			}
		}
	}
	return bestMatch
}

// Set mutates a configuration dynamically into memory without disk IO.
// Exclusively updates the active routing maps and locks correctly.
func (hm *Host) Set(domain string, cfg *alaye.Host) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	domain = zulu.NormalizeHost(domain)
	if domain == emptyString {
		return
	}

	if cfg == nil {
		delete(hm.hosts, domain)
	} else {
		hm.hosts[domain] = cfg
	}

	hm.rebuildLookupLocked()
}

// Save attempts to serialize the current memory host layout down to disk.
// Commits state effectively resolving synchronization boundaries manually.
func (hm *Host) Save(domain string) error {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	cfg, ok := hm.hosts[domain]
	if !ok || cfg == nil {
		return fmt.Errorf("host %q not found", domain)
	}

	filename := zulu.NormalizeHost(domain) + woos.HCLSuffix
	filePath := filepath.Join(hm.hostsDir.Path(), filename)

	p := parser.NewParser(filePath)
	return p.MarshalFile(cfg)
}

// validatePathSegment rejects values that could escape a base directory via path traversal.
// Segments must contain no path separators, no ".." sequences, and must not be empty.
func validatePathSegment(segment string) error {
	if segment == "" {
		return fmt.Errorf("segment cannot be empty")
	}
	if strings.ContainsAny(segment, "/\\") {
		return fmt.Errorf("segment %q contains illegal path separator", segment)
	}
	if strings.Contains(segment, "..") {
		return fmt.Errorf("segment %q contains illegal path traversal sequence", segment)
	}
	return nil
}

// validateACMEToken rejects token values that do not conform to the RFC 8555 token format.
// Valid tokens contain only URL-safe base64 characters: [A-Za-z0-9_-].
func validateACMEToken(token string) error {
	if err := validatePathSegment(token); err != nil {
		return err
	}
	for _, c := range token {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-') {
			return fmt.Errorf("token %q contains invalid character %q", token, c)
		}
	}
	return nil
}

// normalizeHostPath coerces routing constraints into predictable lowercase formats.
// Safeguards against user-induced path definition abnormalities.
func normalizeHostPath(host, path string) (string, string) {
	host = strings.ToLower(strings.TrimSpace(host))
	if path == emptyString {
		path = woos.Slash
	}
	if !strings.HasPrefix(path, woos.Slash) {
		path = woos.Slash + path
	}
	return host, path
}
