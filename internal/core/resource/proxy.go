package resource

import (
	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/pkg/cook"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/ll"
)

// Proxy carries the complete context required to serve a proxied request.
// It groups the three distinct lifetimes that every handler and middleware needs:
// process-lifetime infrastructure (Resource), config-lifetime settings (Global),
// and host-lifetime routing rules (Host).
type Proxy struct {
	Resource    *Resource
	Global      *alaye.Global
	Host        *alaye.Host
	SharedState woos.SharedState
	CookMgr     *cook.Manager
	IPMgr       *zulu.IPManager
}

// Logger returns the process logger from the underlying Resource.
// Provides a single access point so callers never need to reach into Resource directly.
func (p Proxy) Logger() *ll.Logger {
	return p.Resource.Logger
}

// Validate checks that the mandatory fields are populated.
// SharedState and CookMgr are optional and may be nil.
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
