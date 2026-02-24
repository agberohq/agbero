package discovery

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"git.imaxinacion.net/aibox/agbero/internal/core/zulu"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/matcher"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/parser"
	"github.com/fsnotify/fsnotify"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
)

type routeKey struct {
	host string
	path string
}

type routeEntry struct {
	base      alaye.Route
	backends  map[string][]alaye.Server
	lastWrite time.Time
}

type Host struct {
	hostsDir woos.Folder

	mu    sync.RWMutex
	hosts map[string]*alaye.Host

	lookupMap  atomic.Value // map[string]*alaye.Host
	portLookup atomic.Value // map[string]*alaye.Host
	routers    atomic.Value // map[string]*matcher.Tree

	dynamicRoutes map[routeKey]*routeEntry
	nodeIndex     map[string]map[routeKey]struct{}
	nodeFailures  map[string]int

	watcher *fsnotify.Watcher
	logger  *ll.Logger
	changed chan struct{}

	debouncer *jack.Debouncer
	loaded    bool
}

func NewHost(hostsDir string, opts ...Option) *Host {
	return NewHostFolder(woos.NewFolder(hostsDir), opts...)
}

func NewHostFolder(hostsDir woos.Folder, opts ...Option) *Host {
	h := &Host{
		hostsDir:      hostsDir,
		hosts:         make(map[string]*alaye.Host),
		dynamicRoutes: make(map[routeKey]*routeEntry),
		nodeIndex:     make(map[string]map[routeKey]struct{}),
		nodeFailures:  make(map[string]int),
		changed:       make(chan struct{}, 1),
		loaded:        false,
	}
	for _, opt := range opts {
		opt(h)
	}
	if h.logger == nil {
		h.logger = ll.New(woos.Name).Enable()
	}

	h.lookupMap.Store(make(map[string]*alaye.Host))
	h.portLookup.Store(make(map[string]*alaye.Host))
	h.routers.Store(make(map[string]*matcher.Tree))

	h.debouncer = jack.NewDebouncer(
		jack.WithDebounceDelay(500*time.Millisecond),
		jack.WithDebounceMaxWait(2*time.Second),
	)

	return h
}

func normalizeHostPath(host, path string) (string, string) {
	host = strings.ToLower(strings.TrimSpace(host))
	if path == "" {
		path = woos.Slash
	}
	if !strings.HasPrefix(path, woos.Slash) {
		path = woos.Slash + path
	}
	return host, path
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

func (hm *Host) UpdateGossipNode(nodeID, host string, route alaye.Route) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	host, path := normalizeHostPath(host, route.Path)
	if host == "" || nodeID == "" {
		return
	}
	route.Path = path

	servers := route.Backends.Servers
	if len(servers) == 0 {
		return
	}

	for i := range servers {
		if servers[i].Weight <= 0 {
			servers[i].Weight = 1
		}
	}

	k := routeKey{host: host, path: path}

	ent := hm.dynamicRoutes[k]
	if ent == nil {
		base := route
		base.Path = path
		base.Web = alaye.Web{}
		base.Backends.Servers = nil

		if strings.TrimSpace(base.Backends.Strategy) == "" {
			base.Backends.Strategy = alaye.StrategyRandom
		}

		ent = &routeEntry{
			base:      base,
			backends:  make(map[string][]alaye.Server),
			lastWrite: time.Now(),
		}
		hm.dynamicRoutes[k] = ent
	}

	ent.backends[nodeID] = servers
	ent.lastWrite = time.Now()

	if hm.nodeIndex[nodeID] == nil {
		hm.nodeIndex[nodeID] = make(map[routeKey]struct{})
	}
	hm.nodeIndex[nodeID][k] = struct{}{}

	hm.debouncer.Do(hm.rebuildAndNotify)
	hm.logger.Fields("node", nodeID, "host", host, "path", path).Debug("gossip route queued")
}

func (hm *Host) RemoveGossipNode(nodeID string) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	keys := hm.nodeIndex[nodeID]
	if len(keys) == 0 {
		return
	}

	for k := range keys {
		ent := hm.dynamicRoutes[k]
		if ent == nil {
			continue
		}
		delete(ent.backends, nodeID)
		if len(ent.backends) == 0 {
			delete(hm.dynamicRoutes, k)
		} else {
			ent.lastWrite = time.Now()
		}
	}

	delete(hm.nodeIndex, nodeID)

	hm.debouncer.Do(hm.rebuildAndNotify)
	hm.logger.Fields("node", nodeID).Info("gossip node removed")
}

func (hm *Host) rebuildAndNotify() {
	hm.mu.Lock()
	hm.rebuildLookupLocked()
	hm.mu.Unlock()
	hm.logger.Info("router rebuilt from gossip updates")
	hm.notifyChanged()
}

func (hm *Host) RouteExists(host, path string) bool {
	host, path = normalizeHostPath(host, path)
	if host == "" {
		return false
	}

	m := hm.lookupMap.Load().(map[string]*alaye.Host)
	cfg, ok := m[host]
	if !ok || cfg == nil {
		return false
	}
	for _, r := range cfg.Routes {
		p := r.Path
		if p == "" {
			p = woos.Slash
		}
		if p == path {
			return true
		}
	}
	return false
}

func (hm *Host) ResetNodeFailures(nodeName string) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	hm.nodeFailures[nodeName] = 0
	hm.logger.Fields("node", nodeName).Debug("node failures reset")
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
		hm.logger.Fields("dir", hm.hostsDir).Warn("hosts directory does not exist, skipping watch")
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
	debouncedReload := zulu.Debounce(500*time.Millisecond, func() {
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

		if len(cfg.Domains) == 0 {
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
	if hostname == "" {
		return nil
	}

	m := hm.lookupMap.Load().(map[string]*alaye.Host)
	key := hm.resolveDomain(m, hostname)
	if key == "" {
		return nil
	}
	return m[key]
}

func (hm *Host) GetRouter(hostname string) *matcher.Tree {
	hostname = zulu.NormalizeHost(hostname)
	if hostname == "" {
		return nil
	}

	m := hm.lookupMap.Load().(map[string]*alaye.Host)
	key := hm.resolveDomain(m, hostname)
	if key == "" {
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
	for k, v := range m {
		out[k] = v
	}
	return out, nil
}

func (hm *Host) Close() error {
	hm.mu.Lock()
	defer hm.mu.Unlock()

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

func (hm *Host) Set(domain string, cfg *alaye.Host) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	domain = zulu.NormalizeHost(domain)
	if domain == "" {
		return
	}

	// Clone existing maps
	currentLookup := hm.lookupMap.Load().(map[string]*alaye.Host)
	newLookup := make(map[string]*alaye.Host, len(currentLookup)+1)
	for k, v := range currentLookup {
		newLookup[k] = v
	}

	currentRouters := hm.routers.Load().(map[string]*matcher.Tree)
	newRouters := make(map[string]*matcher.Tree, len(currentRouters)+1)
	for k, v := range currentRouters {
		newRouters[k] = v
	}

	newLookup[domain] = cfg

	if cfg != nil && len(cfg.Routes) > 0 {
		tr := matcher.NewTree()
		for i := range cfg.Routes {
			_ = tr.Insert(cfg.Routes[i].Path, &cfg.Routes[i])
		}
		newRouters[domain] = tr
	}

	hm.lookupMap.Store(newLookup)
	hm.routers.Store(newRouters)
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
	domainToRoutes := make(map[string][]alaye.Route)
	domainToConfig := make(map[string]*alaye.Host)

	for _, cfg := range hm.hosts {
		for _, port := range cfg.Bind {
			newPortLookup[port] = cfg
		}
		for _, domain := range cfg.Domains {
			domain = strings.ToLower(strings.TrimSpace(domain))
			if domain == "" {
				continue
			}
			domainToRoutes[domain] = append(domainToRoutes[domain], cfg.Routes...)
			if _, exists := domainToConfig[domain]; !exists {
				domainToConfig[domain] = cfg
			}
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

	dynamicMap := make(map[string][]*alaye.Route)
	for k, ent := range hm.dynamicRoutes {
		if k.host == "" || ent == nil {
			continue
		}
		var servers []alaye.Server
		for _, ss := range ent.backends {
			servers = append(servers, ss...)
		}
		if len(servers) == 0 {
			continue
		}
		rt := ent.base
		rt.Path = k.path
		rt.Web = alaye.Web{}
		rt.Backends.Servers = servers
		dynamicMap[k.host] = append(dynamicMap[k.host], &rt)
	}

	for domain, dynRoutes := range dynamicMap {
		existing, ok := newLookup[domain]
		if ok && existing != nil {
			combined := *existing
			combined.Domains = []string{domain}
			combined.Routes = make([]alaye.Route, len(existing.Routes))
			copy(combined.Routes, existing.Routes)

			byPath := make(map[string]*alaye.Route, len(combined.Routes))
			for i := range combined.Routes {
				p := combined.Routes[i].Path
				if p == "" {
					p = woos.Slash
					combined.Routes[i].Path = woos.Slash
				}
				byPath[p] = &combined.Routes[i]
			}

			for i := range dynRoutes {
				r := dynRoutes[i]
				p := r.Path
				if p == "" {
					p = woos.Slash
					r.Path = woos.Slash
				}
				if ex, ok := byPath[p]; ok {
					ex.Backends.Servers = append(ex.Backends.Servers, r.Backends.Servers...)
				} else {
					combined.Routes = append(combined.Routes, *r)
					byPath[p] = &combined.Routes[len(combined.Routes)-1]
				}
			}
			hm.sortRoutes(combined.Routes)
			newLookup[domain] = &combined
		} else {
			var routes []alaye.Route
			for _, dr := range dynRoutes {
				routes = append(routes, *dr)
			}
			hm.sortRoutes(routes)
			newLookup[domain] = &alaye.Host{
				Domains: []string{domain},
				Routes:  routes,
			}
		}
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
