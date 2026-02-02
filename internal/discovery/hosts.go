package discovery

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core"
	"git.imaxinacion.net/aibox/agbero/internal/core/matcher"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/fsnotify/fsnotify"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/ll"
)

type routeKey struct {
	host string
	path string
}

type routeEntry struct {
	base      alaye.Route
	backends  map[string][]alaye.Server // nodeID -> servers
	lastWrite time.Time
}

type Host struct {
	hostsDir woos.Folder

	mu         sync.RWMutex
	hosts      map[string]*alaye.Host // Loaded from disk (ID -> Config)
	lookupMap  map[string]*alaye.Host // Final O(1) Map (Domain -> Config)
	portLookup map[string]*alaye.Host // Port -> Config (Short-circuit)

	dynamicRoutes map[routeKey]*routeEntry
	nodeIndex     map[string]map[routeKey]struct{}
	nodeFailures  map[string]int

	watcher *fsnotify.Watcher
	logger  *ll.Logger
	changed chan struct{}

	routers map[string]*matcher.Tree

	// loaded indicates if the initial disk scan has completed.
	loaded bool
}

func NewHost(hostsDir string, opts ...Option) *Host {
	return NewHostFolder(woos.NewFolder(hostsDir), opts...)
}

func NewHostFolder(hostsDir woos.Folder, opts ...Option) *Host {
	h := &Host{
		hostsDir:      hostsDir,
		hosts:         make(map[string]*alaye.Host),
		lookupMap:     make(map[string]*alaye.Host),
		portLookup:    make(map[string]*alaye.Host),
		dynamicRoutes: make(map[routeKey]*routeEntry),
		nodeIndex:     make(map[string]map[routeKey]struct{}),
		nodeFailures:  make(map[string]int),
		changed:       make(chan struct{}, 1),
		routers:       make(map[string]*matcher.Tree),
		loaded:        false,
	}
	for _, opt := range opts {
		opt(h)
	}
	if h.logger == nil {
		h.logger = ll.New(woos.Name).Enable()
	}
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

		if strings.TrimSpace(base.Backends.LBStrategy) == "" {
			base.Backends.LBStrategy = alaye.StrategyRandom
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

	hm.rebuildLookupLocked()
	hm.logger.Fields("node", nodeID, "host", host, "path", path).Info("gossip route upserted")
	hm.notifyChanged()
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

	hm.rebuildLookupLocked()
	hm.logger.Fields("node", nodeID).Info("gossip node removed (dynamic backends pruned)")
	hm.notifyChanged()
}

func (hm *Host) RouteExists(host, path string) bool {
	host, path = normalizeHostPath(host, path)
	if host == "" {
		return false
	}

	hm.mu.RLock()
	defer hm.mu.RUnlock()

	cfg, ok := hm.lookupMap[host]
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

	if err := hm.loadAllLocked(); err != nil {
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
	debouncedReload := core.Debounce(500*time.Millisecond, hm.ReloadFull)

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
		"full_path", event.Name,
	).Warn("config change detected, scheduling reload")

	debouncedReload()
}

func (hm *Host) ReloadFull() {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	previousCount := len(hm.lookupMap)

	if err := hm.loadAllLocked(); err != nil {
		hm.logger.Fields("err", err).Error("failed to reload file hosts")
		return
	}

	currentCount := len(hm.lookupMap)
	hm.logger.Fields(
		"previous_hosts", previousCount,
		"current_hosts", currentCount,
		"change", currentCount-previousCount,
	).Info("host configuration reloaded")
	hm.notifyChanged()
}

func (hm *Host) Get(hostname string) *alaye.Host {
	hostname = core.NormalizeHost(hostname)
	if hostname == "" {
		return nil
	}

	hm.mu.RLock()
	defer hm.mu.RUnlock()

	key := hm.resolveDomainLocked(hostname)
	if key == "" {
		return nil
	}
	return hm.lookupMap[key]
}

func (hm *Host) GetRouter(hostname string) *matcher.Tree {
	hostname = core.NormalizeHost(hostname)
	if hostname == "" {
		return nil
	}

	hm.mu.RLock()
	defer hm.mu.RUnlock()

	key := hm.resolveDomainLocked(hostname)
	if key == "" {
		return nil
	}
	return hm.routers[key]
}

func (hm *Host) GetByPort(port string) *alaye.Host {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	return hm.portLookup[port]
}

func (hm *Host) LoadAll() (map[string]*alaye.Host, error) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	// Ensure we load from disk if this is a fresh instance (e.g. CLI usage)
	// that hasn't called Watch().
	if !hm.loaded {
		if err := hm.loadAllLocked(); err != nil {
			return nil, err
		}
	}

	return hm.snapshotLocked(), nil
}

func (hm *Host) Close() error {
	hm.mu.Lock()
	defer hm.mu.Unlock()

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

func (hm *Host) loadAllLocked() error {
	// Mark as loaded regardless of success to prevent infinite loops on error
	hm.loaded = true

	if exists := hm.hostsDir.Exists(""); !exists {
		hm.logger.Fields("hosts_dir", hm.hostsDir).
			Warn("hosts directory not found, clearing configuration")

		hm.hosts = make(map[string]*alaye.Host)
		hm.rebuildLookupLocked()
		return nil
	}

	root := hm.hostsDir.Path()

	nextHosts := make(map[string]*alaye.Host)
	loadedFiles := []string{}
	failedFiles := []string{}
	totalFiles := 0

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

		totalFiles++

		cfg, err := hm.loadOne(p)
		if err != nil {
			hm.logger.Fields(
				"file", name,
				"full_path", p,
				"err", err,
			).Error("failed to load host config")
			failedFiles = append(failedFiles, p)
			return nil
		}

		// Ensure we don't load configs with no domains as they are effectively useless
		if len(cfg.Domains) == 0 {
			hm.logger.Fields("file", name).Warn("host file loaded but contains no 'domains'; ignoring")
			return nil
		}

		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			rel = p
		}
		hostID := strings.TrimSuffix(rel, woos.HCLSuffix)
		hostID = strings.ReplaceAll(hostID, string(filepath.Separator), woos.Slash)

		nextHosts[hostID] = cfg
		loadedFiles = append(loadedFiles, rel)

		primary := ""
		if len(cfg.Domains) > 0 {
			primary = cfg.Domains[0]
		}

		hm.logger.Fields(
			"file", rel,
			"primary_domain", primary,
			"domains", cfg.Domains,
			"routes", len(cfg.Routes),
		).Debug("loaded host config")

		return nil
	})
	if err != nil {
		return errors.Newf("walk hosts dir: %w", err)
	}

	hm.hosts = nextHosts
	hm.rebuildLookupLocked()

	hm.logger.Fields(
		"hosts_dir", hm.hostsDir,
		"total_hcl_files", totalFiles,
		"loaded_files", len(loadedFiles),
		"failed_files", len(failedFiles),
		"host_configs", len(nextHosts),
	).Info("host discovery completed")

	if len(failedFiles) > 0 {
		hm.logger.Fields("failed_files", failedFiles).
			Warn("some host configs failed to load")
	}

	return nil
}

func (hm *Host) rebuildLookupLocked() {
	newLookup := make(map[string]*alaye.Host)
	newPortLookup := make(map[string]*alaye.Host)
	domainToRoutes := make(map[string][]alaye.Route)
	domainToConfig := make(map[string]*alaye.Host)

	// 1) Base Layer: File Hosts
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

			// pick the first config as the "base" config for this domain
			if _, exists := domainToConfig[domain]; !exists {
				domainToConfig[domain] = cfg
			}
		}
	}

	// Materialize file-based hosts into newLookup
	for domain, baseCfg := range domainToConfig {
		combined := *baseCfg
		combined.Domains = []string{domain}

		rts := domainToRoutes[domain]
		combined.Routes = make([]alaye.Route, len(rts))
		copy(combined.Routes, rts)

		hm.sortRoutes(combined.Routes)
		newLookup[domain] = &combined
	}

	// 2) Dynamic Layer: merge dynamicRoutes into lookup
	dynamicMap := make(map[string][]alaye.Route)

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

		dynamicMap[k.host] = append(dynamicMap[k.host], rt)
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

				if ex := byPath[p]; ex != nil {
					ex.Backends.Servers = append(ex.Backends.Servers, r.Backends.Servers...)
					continue
				}

				combined.Routes = append(combined.Routes, r)
				byPath[p] = &combined.Routes[len(combined.Routes)-1]
			}

			hm.sortRoutes(combined.Routes)
			newLookup[domain] = &combined
		} else {
			hm.sortRoutes(dynRoutes)
			newLookup[domain] = &alaye.Host{
				Domains: []string{domain},
				Routes:  dynRoutes,
			}
		}
	}

	// 3) Build Routers
	newRouters := make(map[string]*matcher.Tree, len(newLookup))
	for domain, cfg := range newLookup {
		tr := matcher.NewTree()
		for i := range cfg.Routes {
			rt := &cfg.Routes[i]
			if rt.Path == "" {
				rt.Path = woos.Slash
			}
			_ = tr.Insert(rt.Path, rt)
		}
		newRouters[domain] = tr
	}

	hm.lookupMap = newLookup
	hm.portLookup = newPortLookup
	hm.routers = newRouters
}

func (hm *Host) loadOne(path string) (*alaye.Host, error) {
	var hostConfig alaye.Host
	parser := core.NewParser(path)
	if err := parser.Unmarshal(&hostConfig); err != nil {
		return nil, err
	}
	for i := range hostConfig.Domains {
		hostConfig.Domains[i] = core.NormalizeHost(hostConfig.Domains[i])
	}
	hm.sortRoutes(hostConfig.Routes)
	return &hostConfig, nil
}

func (hm *Host) snapshotLocked() map[string]*alaye.Host {
	out := make(map[string]*alaye.Host, len(hm.lookupMap))
	for k, v := range hm.lookupMap {
		out[k] = v
	}
	return out
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

func (hm *Host) resolveDomainLocked(hostname string) string {
	if _, ok := hm.lookupMap[hostname]; ok {
		return hostname
	}
	for domain := range hm.lookupMap {
		if strings.HasPrefix(domain, "*.") {
			suffix := domain[1:]
			if strings.HasSuffix(hostname, suffix) {
				return domain
			}
		}
	}
	return ""
}
