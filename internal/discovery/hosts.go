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
	checksums map[string]string
	mu        sync.RWMutex
	hostsDir  woos.Folder
	logger    *ll.Logger
	cluster   *cluster.Manager
}

func NewConfigSync(hostsDir woos.Folder, logger *ll.Logger, cluster *cluster.Manager) *ConfigSync {
	return &ConfigSync{
		checksums: make(map[string]string),
		hostsDir:  hostsDir,
		logger:    logger.Namespace(configSyncNamespace),
		cluster:   cluster,
	}
}

func (c *ConfigSync) ShouldBroadcast(domain string, content []byte) bool {
	checksum := c.calculateChecksum(content)

	c.mu.Lock()
	defer c.mu.Unlock()

	if existing := c.checksums[domain]; existing == checksum {
		return false
	}

	c.checksums[domain] = checksum
	return true
}

func (c *ConfigSync) ApplyClusterConfig(domain string, rawHCL []byte, deleted bool) error {
	checksum := c.calculateChecksum(rawHCL)

	c.mu.Lock()
	c.checksums[domain] = checksum
	c.mu.Unlock()

	path := filepath.Join(c.hostsDir.Path(), domain+woos.HCLSuffix)

	if deleted {
		return os.Remove(path)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, rawHCL, woos.FilePerm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (c *ConfigSync) calculateChecksum(data []byte) string {
	if len(data) == zeroValue {
		return emptyString
	}
	hash := zulu.XXHash(data)
	return hash
}

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

func WithClusterManager(cm *cluster.Manager) Option {
	return func(h *Host) {
		h.clusterMgr = cm
		if cm != nil {
			h.configSync = NewConfigSync(h.hostsDir, h.logger, cm)
		}
	}
}

func (hm *Host) OnClusterConfigChange(domain string, rawHCL []byte, deleted bool) {
	if hm.configSync == nil {
		return
	}

	if err := hm.configSync.ApplyClusterConfig(domain, rawHCL, deleted); err != nil {
		hm.logger.Fields("domain", domain, "err", err).Error("failed to apply cluster config")
		return
	}

	hm.logger.Fields("domain", domain, "deleted", deleted).Info("cluster config applied")
}

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

func (hm *Host) handleRouteDeletion(key string) {
	hm.mu.Lock()
	delete(hm.clusterRoutes, key)
	hm.mu.Unlock()

	hm.lifetimes.CancelTimed(key)

	hm.logger.Fields("key", key).Info("cluster route removed")
	hm.debouncer.Do(hm.rebuildAndNotify)
}

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

func (hm *Host) rebuildAndNotify() {
	hm.mu.Lock()
	hm.rebuildLookupLocked()
	hm.mu.Unlock()
	hm.logger.Info("router rebuilt from updates")
	hm.notifyChanged()
}

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

	if hm.clusterMgr != nil && event.Has(fsnotify.Write) {
		content, err := os.ReadFile(event.Name)
		if err == nil {
			domain := strings.TrimSuffix(filepath.Base(event.Name), woos.HCLSuffix)
			if hm.configSync.ShouldBroadcast(domain, content) {
				go hm.clusterMgr.BroadcastConfig(domain, content, false)
			}
		}
	}

	hm.logger.Fields(
		"event", event.Op.String(),
		"file", filepath.Base(event.Name),
	).Debug("config change detected, scheduling reload")

	debouncedReload()
}

func (hm *Host) ReloadFull() error {
	if err := hm.loadInternal(); err != nil {
		return err
	}
	hm.notifyChanged()
	return nil
}

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

func (hm *Host) GetByPort(port string) *alaye.Host {
	m := hm.portLookup.Load().(map[string]*alaye.Host)
	return m[port]
}

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

func (hm *Host) Changed() <-chan struct{} {
	return hm.changed
}

func (hm *Host) notifyChanged() {
	select {
	case hm.changed <- struct{}{}:
	default:
	}
}

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
			defaultHost := alaye.NewStaticHost(host, emptyString, true)
			defaultHost.Routes = nil
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

func (hm *Host) hostsDirExists() bool {
	p := hm.hostsDir.Path()
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func (hm *Host) sortRoutes(routes []alaye.Route) {
	sort.SliceStable(routes, func(i, j int) bool {
		return len(routes[i].Path) > len(routes[j].Path)
	})
}

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
