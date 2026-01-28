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

// routeEntry holds stable route policy + dynamic backends (from nodes)
type routeEntry struct {
	base      alaye.Route
	backends  map[string][]alaye.Server // nodeID -> servers
	lastWrite time.Time
}

type Host struct {
	hostsDir woos.Folder

	mu        sync.RWMutex
	hosts     map[string]*alaye.Host // Loaded from disk (ID -> Config)
	lookupMap map[string]*alaye.Host // Final O(1) Map (Domain -> Config)

	// Dynamic routing table: (host,path) -> entry
	dynamicRoutes map[routeKey]*routeEntry

	// Node index: nodeID -> set of routeKeys it registered
	nodeIndex map[string]map[routeKey]struct{}

	// Per-node failure tracking
	nodeFailures map[string]int

	watcher *fsnotify.Watcher
	logger  *ll.Logger
	changed chan struct{}

	routers    map[string]*matcher.Tree
	portLookup map[string]*alaye.Host
}

// NewHost creates a new host discovery manager (compatible with string)
func NewHost(hostsDir string, opts ...Option) *Host {
	return NewHostFolder(woos.NewFolder(hostsDir), opts...)
}

// NewHostFolder creates a new host discovery manager with Folder type
func NewHostFolder(hostsDir woos.Folder, opts ...Option) *Host {
	h := &Host{
		hostsDir:      hostsDir,
		hosts:         make(map[string]*alaye.Host),
		lookupMap:     make(map[string]*alaye.Host),
		portLookup:    make(map[string]*alaye.Host), // NEW
		dynamicRoutes: make(map[routeKey]*routeEntry),
		nodeIndex:     make(map[string]map[routeKey]struct{}),
		nodeFailures:  make(map[string]int),
		changed:       make(chan struct{}, 1),
		routers:       make(map[string]*matcher.Tree),
	}
	for _, opt := range opts {
		opt(h)
	}
	if h.logger == nil {
		h.logger = ll.New(woos.Name).Enable()
	}
	return h
}

// UpdateGossipNode upserts (merges) a dynamic route from a gossip node.
// This never rejects duplicates; duplicates are merged at (host,path) and servers are aggregated.
func (hm *Host) UpdateGossipNode(nodeID, host string, route alaye.Route) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	host, path := normalizeHostPath(host, route.Path)
	if host == "" || nodeID == "" {
		return
	}
	route.Path = path

	// Must have at least one backend server for a proxy route.
	servers := route.Backends.Servers
	if len(servers) == 0 {
		return
	}

	// Normalize weights.
	for i := range servers {
		if servers[i].Weight <= 0 {
			servers[i].Weight = 1
		}
	}

	k := routeKey{host: host, path: path}

	ent := hm.dynamicRoutes[k]
	if ent == nil {
		// Keep stable policy knobs in base, but rebuild Servers from ent.backends.
		base := route
		base.Path = path

		// Ensure proxy/web XOR invariant for dynamic routes.
		base.Web = alaye.Web{}
		base.Backends.Servers = nil

		// Default strategy if empty.
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

	// Replace this node's contribution for this route (idempotent).
	ent.backends[nodeID] = servers
	ent.lastWrite = time.Now()

	// Update node index for fast cleanup.
	if hm.nodeIndex[nodeID] == nil {
		hm.nodeIndex[nodeID] = make(map[routeKey]struct{})
	}
	hm.nodeIndex[nodeID][k] = struct{}{}

	hm.rebuildLookupLocked()
	hm.logger.Fields("node", nodeID, "host", host, "path", path).Info("gossip route upserted")
	hm.notifyChanged()
}

// RemoveGossipNode removes all dynamic backends contributed by a node.
// If a route ends up with zero backends, it is removed entirely.
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

// RouteExists returns true if the merged lookup (file + dynamic) contains host+path.
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
			p = "/"
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

	// Check if hosts directory exists
	if exists := hm.hostsDir.Exists(""); exists {
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
	// Debounce set to 500ms
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

	// If a new directory is created, start watching it too.
	if event.Has(fsnotify.Create) {
		if fi, err := os.Stat(event.Name); err == nil && fi.IsDir() {
			_ = hm.addWatchRecursive(event.Name)
			return
		}
	}

	name := strings.ToLower(event.Name)
	if !strings.HasSuffix(name, ".hcl") {
		return
	}

	hm.logger.Fields(
		"event", event.Op.String(),
		"file", filepath.Base(event.Name),
		"full_path", event.Name,
	).Info("config change detected, scheduling reload")

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
	return hm.lookupMap[hostname]
}

func (hm *Host) LoadAll() (map[string]*alaye.Host, error) {
	hm.mu.Lock()
	defer hm.mu.Unlock()
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

func (hm *Host) GetRouter(hostname string) *matcher.Tree {
	hostname = core.NormalizeHost(hostname)
	if hostname == "" {
		return nil
	}
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	return hm.routers[hostname]
}

func (hm *Host) notifyChanged() {
	select {
	case hm.changed <- struct{}{}:
	default:
	}
}

func (hm *Host) loadAllLocked() error {
	// Check if hosts directory exists using Folder method
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
		if !strings.HasSuffix(strings.ToLower(name), ".hcl") {
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
			return nil // continue walking
		}

		// hostID is only an internal key; make it stable + unique across subdirs.
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			rel = p
		}
		hostID := strings.TrimSuffix(rel, ".hcl")
		hostID = strings.ReplaceAll(hostID, string(filepath.Separator), "/")

		nextHosts[hostID] = cfg
		loadedFiles = append(loadedFiles, rel)

		primary := ""
		if len(cfg.Domains) > 0 {
			primary = cfg.Domains[0]
		}

		hm.logger.Fields(
			"file", rel,
			"primary_domain", primary,
			"domains", cfg.Domains, // or count + first N
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
	newPortLookup := make(map[string]*alaye.Host) // NEW
	domainToRoutes := make(map[string][]alaye.Route)
	domainToConfig := make(map[string]*alaye.Host)

	// 1) Base Layer: File Hosts
	for _, cfg := range hm.hosts {
		// NEW: Populate Port Lookup
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

	// ... [Rest of logic for Routes and Dynamic entries remains the same] ...
	// ... (domainToRoutes processing loop) ...
	for domain, routes := range domainToRoutes {
		baseCfg := domainToConfig[domain]
		if baseCfg == nil {
			continue
		}
		merged := *baseCfg
		merged.Domains = []string{domain}
		merged.Routes = make([]alaye.Route, len(routes))
		copy(merged.Routes, routes)
		sortRoutes(merged.Routes)
		newLookup[domain] = &merged
	}

	// ... (dynamicRoutes processing loop) ...
	// (Copy the dynamic logic from original file)
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
					p = "/"
					combined.Routes[i].Path = "/"
				}
				byPath[p] = &combined.Routes[i]
			}
			for i := range dynRoutes {
				r := dynRoutes[i]
				p := r.Path
				if p == "" {
					p = "/"
					r.Path = "/"
				}
				if ex := byPath[p]; ex != nil {
					ex.Backends.Servers = append(ex.Backends.Servers, r.Backends.Servers...)
					continue
				}
				combined.Routes = append(combined.Routes, r)
				byPath[p] = &combined.Routes[len(combined.Routes)-1]
			}
			sortRoutes(combined.Routes)
			newLookup[domain] = &combined
		} else {
			sortRoutes(dynRoutes)
			newLookup[domain] = &alaye.Host{
				Domains: []string{domain},
				Routes:  dynRoutes,
			}
		}
	}

	newRouters := make(map[string]*matcher.Tree, len(newLookup))
	for domain, cfg := range newLookup {
		tr := matcher.NewTree()
		for i := range cfg.Routes {
			rt := &cfg.Routes[i]
			if rt.Path == "" {
				rt.Path = "/"
			}
			_ = tr.Insert(rt.Path, rt)
		}
		newRouters[domain] = tr
	}

	hm.lookupMap = newLookup
	hm.portLookup = newPortLookup // NEW
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
	sortRoutes(hostConfig.Routes)
	return &hostConfig, nil
}

func (hm *Host) snapshotLocked() map[string]*alaye.Host {
	out := make(map[string]*alaye.Host, len(hm.lookupMap))
	for k, v := range hm.lookupMap {
		out[k] = v
	}
	return out
}

func (hm *Host) GetByPort(port string) *alaye.Host {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	return hm.portLookup[port]
}

// normalizeHostPath makes host+path stable and safe.
func normalizeHostPath(host, path string) (string, string) {
	host = strings.ToLower(strings.TrimSpace(host))
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return host, path
}

func sortRoutes(routes []alaye.Route) {
	sort.SliceStable(routes, func(i, j int) bool {
		return len(routes[i].Path) > len(routes[j].Path)
	})
}
