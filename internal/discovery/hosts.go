package discovery

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"github.com/fsnotify/fsnotify"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/ll"
)

// DynamicRouteItem represents a single route from a single gossip node
type DynamicRouteItem struct {
	Host  string
	Route woos.Route
}

type Host struct {
	hostsDir string

	mu        sync.RWMutex
	hosts     map[string]*woos.HostConfig // Loaded from disk (ID -> Config)
	lookupMap map[string]*woos.HostConfig // Final O(1) Map (Domain -> Config)

	// Map of NodeName -> Route Definition
	gossipRoutes map[string]DynamicRouteItem

	// Per-node failure tracking
	nodeFailures map[string]int

	watcher *fsnotify.Watcher
	logger  *ll.Logger
	changed chan struct{}
}

func NewHost(hostsDir string, opts ...Option) *Host {
	h := &Host{
		hostsDir:     hostsDir,
		hosts:        make(map[string]*woos.HostConfig),
		lookupMap:    make(map[string]*woos.HostConfig),
		gossipRoutes: make(map[string]DynamicRouteItem),
		nodeFailures: make(map[string]int),
		changed:      make(chan struct{}, 1),
	}

	for _, opt := range opts {
		opt(h)
	}

	if h.logger == nil {
		h.logger = ll.New(woos.Name).Enable()
	}

	return h
}

func (hm *Host) UpdateGossipNode(nodeID, host string, route woos.Route) {
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

	if _, err := os.Stat(hm.hostsDir); err == nil {
		if err := hm.watcher.Add(hm.hostsDir); err != nil {
			_ = hm.watcher.Close()
			return err
		}
		go hm.watchLoop()
		hm.logger.Fields("dir", hm.hostsDir).Info("host discovery watching")
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
	hm.logger.Fields("event", event.Op.String(), "file", event.Name).Info("config change detected")
	debouncedReload()
}

func (hm *Host) ReloadFull() {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	if err := hm.loadAllLocked(); err != nil {
		hm.logger.Fields("err", err).Error("failed to reload file hosts")
		return
	}
	hm.notifyChanged()
}

func (hm *Host) Get(hostname string) *woos.HostConfig {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	if hostname == "" {
		return nil
	}

	hm.mu.RLock()
	defer hm.mu.RUnlock()

	return hm.lookupMap[hostname]
}

func (hm *Host) LoadAll() (map[string]*woos.HostConfig, error) {
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

func (hm *Host) notifyChanged() {
	select {
	case hm.changed <- struct{}{}:
	default:
	}
}

func (hm *Host) loadAllLocked() error {
	if _, err := os.Stat(hm.hostsDir); err != nil {
		hm.hosts = make(map[string]*woos.HostConfig)
		hm.rebuildLookupLocked()
		return nil
	}

	files, err := os.ReadDir(hm.hostsDir)
	if err != nil {
		return errors.Newf("read hosts dir: %w", err)
	}

	nextHosts := make(map[string]*woos.HostConfig, len(files))

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		name := file.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".hcl") {
			continue
		}

		path := filepath.Join(hm.hostsDir, name)
		cfg, err := hm.loadOne(path)
		if err != nil {
			return errors.Newf("load host %q: %w", name, err)
		}

		hostID := strings.TrimSuffix(name, ".hcl")
		nextHosts[hostID] = cfg
	}

	hm.hosts = nextHosts
	hm.rebuildLookupLocked()
	return nil
}

func (hm *Host) rebuildLookupLocked() {
	newLookup := make(map[string]*woos.HostConfig)

	// 1. Add File Hosts (Base Layer)
	for _, cfg := range hm.hosts {
		for _, domain := range cfg.Domains {
			newLookup[domain] = cfg
		}
	}

	// 2. Merge Gossip Routes
	dynamicMap := make(map[string][]*woos.Route)
	for _, item := range hm.gossipRoutes {
		dynamicMap[item.Host] = append(dynamicMap[item.Host], &item.Route)
	}

	for domain, routes := range dynamicMap {
		existing, ok := newLookup[domain]

		if ok {
			// Host exists in File: Append routes dynamically.
			// Perform Deep Copy of existing config to avoid mutating the base 'hosts' map
			combined := *existing

			// Deep copy Routes slice
			combined.Routes = make([]woos.Route, len(existing.Routes))
			copy(combined.Routes, existing.Routes)

			// Track existing paths to prevent duplicates
			seen := make(map[string]bool)
			for _, r := range combined.Routes {
				seen[r.Path] = true
			}

			// Append gossip routes ONLY if path doesn't exist in file config
			for _, r := range routes {
				if !seen[r.Path] {
					combined.Routes = append(combined.Routes, *r)
					seen[r.Path] = true
				}
			}
			sortRoutes(combined.Routes)

			newLookup[domain] = &combined
		} else {
			// Host is purely dynamic
			sorted := derefRoutes(routes)
			sortRoutes(sorted)

			newLookup[domain] = &woos.HostConfig{
				Domains: []string{domain},
				Routes:  sorted,
			}
		}
	}

	hm.lookupMap = newLookup
}

func (hm *Host) loadOne(path string) (*woos.HostConfig, error) {
	var hostConfig woos.HostConfig
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

func (hm *Host) snapshotLocked() map[string]*woos.HostConfig {
	out := make(map[string]*woos.HostConfig, len(hm.lookupMap))
	for k, v := range hm.lookupMap {
		out[k] = v
	}
	return out
}

func derefRoutes(in []*woos.Route) []woos.Route {
	out := make([]woos.Route, len(in))
	for i, r := range in {
		out[i] = *r
	}
	return out
}

func sortRoutes(routes []woos.Route) {
	sort.SliceStable(routes, func(i, j int) bool {
		return len(routes[i].Path) > len(routes[j].Path)
	})
}
