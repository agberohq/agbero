package discovery

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"github.com/fsnotify/fsnotify"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/ll"
)

type Host struct {
	hostsDir string

	mu    sync.RWMutex
	hosts map[string]*woos.HostConfig

	watcher *fsnotify.Watcher
	logger  *ll.Logger

	// Optional: notify subscribers on change
	changed chan struct{}
}

func NewHost(hostsDir string, opts ...Option) *Host {
	h := &Host{
		hostsDir: hostsDir,
		hosts:    make(map[string]*woos.HostConfig),
		changed:  make(chan struct{}, 1),
	}

	for _, opt := range opts {
		opt(h)
	}

	if h.logger == nil {
		h.logger = ll.New(woos.Name).Enable()
	}

	return h
}

// Watch starts fsnotify watching and performs an initial load.
func (hm *Host) Watch() error {
	var err error
	hm.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	// Initial load (fail fast if directory missing or unreadable)
	if err := hm.loadAllLocked(); err != nil {
		_ = hm.watcher.Close()
		return err
	}

	// Watch directory
	if err := hm.watcher.Add(hm.hostsDir); err != nil {
		_ = hm.watcher.Close()
		return err
	}

	go hm.watchLoop()
	hm.logger.Fields("dir", hm.hostsDir).Info("host discovery watching")
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
	// Ignore non-hcl files
	if !strings.HasSuffix(strings.ToLower(event.Name), ".hcl") {
		return
	}

	filename := filepath.Base(event.Name)
	hostID := strings.TrimSuffix(filename, ".hcl")

	// Remove
	if event.Op&fsnotify.Remove == fsnotify.Remove {
		hm.mu.Lock()
		delete(hm.hosts, hostID)
		hm.mu.Unlock()

		hm.logger.Fields("host_id", hostID).Info("host removed")
		hm.notifyChanged()
		return
	}

	// Create / Write / Rename -> reload file
	cfg, err := hm.loadOne(event.Name)
	if err != nil {
		hm.logger.Fields("file", event.Name, "err", err.Error()).Warn("failed to load host config")
		return
	}

	hm.mu.Lock()
	hm.hosts[hostID] = cfg
	hm.mu.Unlock()

	hm.logger.Fields("host_id", hostID).Info("host updated")
	hm.notifyChanged()
}

// Get finds a host config by matching a configured domain.
// NOTE: Server should normalize host (strip port) before calling Get.
func (hm *Host) Get(hostname string) *woos.HostConfig {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	if hostname == "" {
		return nil
	}

	hm.mu.RLock()
	defer hm.mu.RUnlock()

	for _, hc := range hm.hosts {
		// CHANGED: server_names -> Domains
		for _, domain := range hc.Domains {
			if strings.EqualFold(domain, hostname) {
				return hc
			}
		}
	}
	return nil
}

// LoadAll loads all host configs from disk and returns a snapshot map.
// Safe for callers; does not return the internal map.
func (hm *Host) LoadAll() (map[string]*woos.HostConfig, error) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	if err := hm.loadAllLocked(); err != nil {
		return nil, err
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

// Changed returns a channel that receives a signal (non-blocking) on any update/removal.
func (hm *Host) Changed() <-chan struct{} {
	return hm.changed
}

func (hm *Host) notifyChanged() {
	select {
	case hm.changed <- struct{}{}:
	default:
		// coalesce bursts
	}
}

func (hm *Host) loadAllLocked() error {
	// Ensure directory exists
	if _, err := os.Stat(hm.hostsDir); err != nil {
		return errors.Newf("hosts dir: %w", err)
	}

	files, err := os.ReadDir(hm.hostsDir)
	if err != nil {
		return errors.Newf("read hosts dir: %w", err)
	}

	// Build new map to avoid partially-updated state on error
	next := make(map[string]*woos.HostConfig, len(files))

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
		next[hostID] = cfg
	}

	hm.hosts = next
	hm.logger.Fields("hosts", len(hm.hosts)).Info("hosts loaded")
	return nil
}

func (hm *Host) loadOne(path string) (*woos.HostConfig, error) {
	var hostConfig woos.HostConfig

	// NOTE: your Parser is not generic; use NewParser(path).Unmarshal(&hostConfig)
	parser := woos.NewParser(path)
	if err := parser.Unmarshal(&hostConfig); err != nil {
		return nil, err
	}

	// Normalize domains to lowercase for matching
	for i := range hostConfig.Domains {
		hostConfig.Domains[i] = strings.ToLower(strings.TrimSpace(hostConfig.Domains[i]))
	}

	return &hostConfig, nil
}

func (hm *Host) snapshotLocked() map[string]*woos.HostConfig {
	out := make(map[string]*woos.HostConfig, len(hm.hosts))
	for k, v := range hm.hosts {
		out[k] = v
	}
	return out
}
