package discovery

import (
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

// DynamicRouteItem represents a single route from a single gossip node
type DynamicRouteItem struct {
	Host  string
	Route alaye.Route
}

type Host struct {
	hostsDir woos.Folder

	mu        sync.RWMutex
	hosts     map[string]*alaye.Host // Loaded from disk (ID -> Config)
	lookupMap map[string]*alaye.Host // Final O(1) Map (Domain -> Config)

	// Map of NodeName -> Route Definition
	gossipRoutes map[string]DynamicRouteItem

	// Per-node failure tracking
	nodeFailures map[string]int

	watcher *fsnotify.Watcher
	logger  *ll.Logger
	changed chan struct{}

	routers map[string]*matcher.Tree
}

// NewHost creates a new host discovery manager (compatible with string)
func NewHost(hostsDir string, opts ...Option) *Host {
	h := &Host{
		hostsDir:     woos.NewFolder(hostsDir),
		hosts:        make(map[string]*alaye.Host),
		lookupMap:    make(map[string]*alaye.Host),
		gossipRoutes: make(map[string]DynamicRouteItem),
		nodeFailures: make(map[string]int),
		changed:      make(chan struct{}, 1),
		routers:      make(map[string]*matcher.Tree),
	}

	for _, opt := range opts {
		opt(h)
	}

	if h.logger == nil {
		h.logger = ll.New(woos.Name).Enable()
	}

	return h
}

// NewHostFolder creates a new host discovery manager with Folder type
func NewHostFolder(hostsDir woos.Folder, opts ...Option) *Host {
	h := &Host{
		hostsDir:     hostsDir,
		hosts:        make(map[string]*alaye.Host),
		lookupMap:    make(map[string]*alaye.Host),
		gossipRoutes: make(map[string]DynamicRouteItem),
		nodeFailures: make(map[string]int),
		changed:      make(chan struct{}, 1),
		routers:      make(map[string]*matcher.Tree),
	}

	for _, opt := range opts {
		opt(h)
	}

	if h.logger == nil {
		h.logger = ll.New(woos.Name).Enable()
	}

	return h
}

func (hm *Host) UpdateGossipNode(nodeID, host string, route alaye.Route) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	host = strings.ToLower(strings.TrimSpace(host))
	hm.gossipRoutes[nodeID] = DynamicRouteItem{
		Host:  host,
		Route: route,
	}

	hm.rebuildLookupLocked()
	hm.logger.Fields("node", nodeID, "host", host, "path", route.Path).Info("gossip route updated")
	hm.notifyChanged()
}

func (hm *Host) RemoveGossipNode(nodeID string) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	if _, exists := hm.gossipRoutes[nodeID]; !exists {
		return
	}

	delete(hm.gossipRoutes, nodeID)
	hm.rebuildLookupLocked()

	hm.logger.Fields("node", nodeID).Info("gossip node removed")
	hm.notifyChanged()
}

func (hm *Host) RouteExists(host, path string) bool {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	cfg, ok := hm.lookupMap[host]
	if !ok {
		return false
	}
	for _, r := range cfg.Routes {
		if r.Path == path {
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
		if err := hm.watcher.Add(hm.hostsDir.Path()); err != nil {
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
	hostname = strings.ToLower(strings.TrimSpace(hostname))
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
	hostname = strings.ToLower(strings.TrimSpace(hostname))
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
		hm.logger.Fields(
			"hosts_dir", hm.hostsDir,
		).Warn("hosts directory not found, clearing configuration")

		hm.hosts = make(map[string]*alaye.Host)
		hm.rebuildLookupLocked()
		return nil
	}

	// Read directory using Folder.Read()
	entries, err := hm.hostsDir.Read()
	if err != nil {
		return errors.Newf("read hosts dir: %w", err)
	}

	nextHosts := make(map[string]*alaye.Host, len(entries))
	loadedFiles := []string{}
	failedFiles := []string{}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".hcl") {
			continue
		}

		path := filepath.Join(hm.hostsDir.Path(), name)
		cfg, err := hm.loadOne(path)
		if err != nil {
			hm.logger.Fields(
				"file", name,
				"err", err,
			).Error("failed to load host config")
			failedFiles = append(failedFiles, name)
			continue
		}

		hostID := strings.TrimSuffix(name, ".hcl")
		nextHosts[hostID] = cfg
		loadedFiles = append(loadedFiles, name)

		hm.logger.Fields(
			"file", name,
			"host_id", hostID,
			"domains", len(cfg.Domains),
			"routes", len(cfg.Routes),
		).Debug("loaded host config")
	}

	hm.hosts = nextHosts
	hm.rebuildLookupLocked()

	hm.logger.Fields(
		"hosts_dir", hm.hostsDir,
		"total_files", len(entries),
		"loaded_files", len(loadedFiles),
		"failed_files", len(failedFiles),
		"host_configs", len(nextHosts),
	).Info("host discovery completed")

	if len(failedFiles) > 0 {
		hm.logger.Fields("failed_files", failedFiles).Warn("some host configs failed to load")
	}

	return nil
}

func (hm *Host) rebuildLookupLocked() {
	// Caller MUST hold hm.mu.Lock()

	newLookup := make(map[string]*alaye.Host)
	domainToRoutes := make(map[string][]alaye.Route)
	domainToConfig := make(map[string]*alaye.Host)

	// 1) Base Layer: File Hosts
	for _, cfg := range hm.hosts {
		for _, domain := range cfg.Domains {
			domain = strings.ToLower(strings.TrimSpace(domain))
			if domain == "" {
				continue
			}

			// IMPORTANT: always create the domain key, even if cfg.Routes is empty.
			domainToRoutes[domain] = append(domainToRoutes[domain], cfg.Routes...)

			// first config becomes template (TLS, Limits, etc.)
			if _, exists := domainToConfig[domain]; !exists {
				domainToConfig[domain] = cfg
			}
		}
	}

	// Create merged host configs from file layer
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

	// 2) Merge Gossip Routes (overlay)
	dynamicMap := make(map[string][]*alaye.Route)
	for _, item := range hm.gossipRoutes {
		domain := strings.ToLower(strings.TrimSpace(item.Host))
		if domain == "" {
			continue
		}
		dynamicMap[domain] = append(dynamicMap[domain], &item.Route)
	}

	for domain, routes := range dynamicMap {
		existing, ok := newLookup[domain]

		if ok {
			combined := *existing
			combined.Domains = []string{domain}

			combined.Routes = make([]alaye.Route, len(existing.Routes))
			copy(combined.Routes, existing.Routes)

			seen := make(map[string]bool, len(combined.Routes))
			for i := range combined.Routes {
				p := combined.Routes[i].Path
				if p == "" {
					p = "/"
				}
				seen[p] = true
			}

			for _, r := range routes {
				if r == nil {
					continue
				}
				p := r.Path
				if p == "" {
					p = "/"
				}
				if seen[p] {
					continue
				}
				combined.Routes = append(combined.Routes, *r)
				seen[p] = true
			}

			sortRoutes(combined.Routes)
			newLookup[domain] = &combined
		} else {
			sorted := derefRoutes(routes)
			sortRoutes(sorted)

			newLookup[domain] = &alaye.Host{
				Domains: []string{domain},
				Routes:  sorted,
			}
		}
	}

	// 3) Build Routers from final merged configs
	newRouters := make(map[string]*matcher.Tree, len(newLookup))

	for domain, cfg := range newLookup {
		tr := matcher.NewTree()

		// Insert using stable pointers to slice elements.
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
	hm.routers = newRouters
}

func (hm *Host) loadOne(path string) (*alaye.Host, error) {
	var hostConfig alaye.Host
	parser := core.NewParser(path)
	if err := parser.Unmarshal(&hostConfig); err != nil {
		return nil, err
	}
	for i := range hostConfig.Domains {
		hostConfig.Domains[i] = strings.ToLower(strings.TrimSpace(hostConfig.Domains[i]))
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

func derefRoutes(in []*alaye.Route) []alaye.Route {
	out := make([]alaye.Route, len(in))
	for i, r := range in {
		out[i] = *r
	}
	return out
}

func sortRoutes(routes []alaye.Route) {
	sort.SliceStable(routes, func(i, j int) bool {
		return len(routes[i].Path) > len(routes[j].Path)
	})
}
