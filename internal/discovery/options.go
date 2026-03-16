package discovery

import (
	"github.com/agberohq/agbero/internal/cluster"
	"github.com/fsnotify/fsnotify"
	"github.com/olekukonko/ll"
)

type Option func(host *Host)

func WithLogger(logger *ll.Logger) Option {
	return func(host *Host) {
		host.logger = logger
	}
}

func WithWatcher(watcher *fsnotify.Watcher) Option {
	return func(host *Host) {
		host.watcher = watcher
	}
}

// WithClusterManager configures cluster support for the host discovery module.
// Enables automatic synchronization of local file changes with the broader network.
func WithClusterManager(cm *cluster.Manager) Option {
	return func(h *Host) {
		h.clusterMgr = cm
		if cm != nil {
			h.configSync = NewConfigSync(h.logger, cm)
		}
	}
}
