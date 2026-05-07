// Package resource defines context structures for routing and traffic handling.
// It facilitates dependency injection for HTTP route and proxy handlers.
package resource

import (
	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/hub/cook"
	"github.com/agberohq/agbero/internal/hub/orchestrator"
	"github.com/agberohq/agbero/internal/pkg/tunnel"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/ll"
)

type Proxy struct {
	Resource    *Resource
	Global      *alaye.Global
	Host        *alaye.Host
	SharedState woos.SharedState
	CookMgr     *cook.Manager
	IPMgr       *zulu.IPManager
	Orch        *orchestrator.Manager
	// TunnelPools is the global registry of named SOCKS5 tunnel pools.
	// Routes reference tunnels by name via the backend `via` attribute.
	TunnelPools map[string]*tunnel.Pool
}

// Logger provides access to the namespaced system logger from the resource manager.
// This ensures that all proxy-related events are logged consistently.
func (p Proxy) Logger() *ll.Logger {
	return p.Resource.Logger
}

// Validate ensures that all mandatory proxy dependencies are correctly initialized.
// It performs integrity checks on the resource, global config, and host configuration.
func (p Proxy) Validate() error {
	if p.Resource == nil {
		return errors.New("proxy: resource manager is required")
	}
	if p.Global == nil {
		return errors.New("proxy: global config is required")
	}
	if p.Host == nil {
		return errors.New("proxy: host config is required")
	}

	if len(p.Host.Domains) == 0 {
		return errors.New("proxy: host must have at least one domain")
	}

	return p.Resource.Validate()
}
