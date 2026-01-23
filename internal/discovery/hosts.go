// internal/discovery/hosts.go
package discovery

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

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
	// We store raw inputs so we can rebuild/merge efficiently on changes
	gossipRoutes map[string]DynamicRouteItem

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

// UpdateGossipNode adds or updates a route from a specific node
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

// RemoveGossipNode removes all routes associated with a node
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
	for {
		select {
		case event, ok := <-hm.watcher.Events:
			if !ok {
				return
			}
			hm.handleEvent(event)

		case err, ok := <-hm.watcher.Errors:
			if !ok {
				return
			}
			hm.logger.Fields("err", err.Error()).Error("watcher error")
		}
	}
}

func (hm *Host) handleEvent(event fsnotify.Event) {
	if !strings.HasSuffix(strings.ToLower(event.Name), ".hcl") {
		return
	}
	hm.reloadFull()
}

func (hm *Host) reloadFull() {
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

// rebuildLookupLocked merges File hosts and Dynamic Routes
func (hm *Host) rebuildLookupLocked() {
	newLookup := make(map[string]*woos.HostConfig)

	// 1. Add File Hosts (Base Layer)
	for _, cfg := range hm.hosts {
		// Clone config to avoid mutation issues if we were to modify it
		// (Optional optimization: simple pointer copy since files are immutable until reload)
		for _, domain := range cfg.Domains {
			newLookup[domain] = cfg
		}
	}

	// 2. Merge Gossip Routes
	// We need to group gossip routes by Host
	dynamicMap := make(map[string][]*woos.Route)

	for _, item := range hm.gossipRoutes {
		dynamicMap[item.Host] = append(dynamicMap[item.Host], &item.Route)
	}

	for domain, routes := range dynamicMap {
		existing, ok := newLookup[domain]

		if ok {
			// Host exists in File: Append routes dynamically
			// We must create a shallow copy of the struct to not affect the base map
			// which might be shared (though here we just rebuilt hosts map, so safer).
			// To be 100% safe against race conditions on the pointer from `hm.hosts`,
			// we create a new HostConfig combining them.
			combined := *existing // Shallow copy

			// Append gossip routes.
			// Note: We might want to sort routes by path length (longest first) for correct matching logic
			combined.Routes = append(combined.Routes, derefRoutes(routes)...)
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
	parser := woos.NewParser(path)
	if err := parser.Unmarshal(&hostConfig); err != nil {
		return nil, err
	}
	for i := range hostConfig.Domains {
		hostConfig.Domains[i] = strings.ToLower(strings.TrimSpace(hostConfig.Domains[i]))
	}
	// Sort file routes too
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

// sortRoutes sorts routes by Path length descending.
// This ensures "/api/v1" is matched before "/api" or "/".
func sortRoutes(routes []woos.Route) {
	sort.SliceStable(routes, func(i, j int) bool {
		return len(routes[i].Path) > len(routes[j].Path)
	})
}
