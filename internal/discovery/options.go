package discovery

import (
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
