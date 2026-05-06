package xhttp

import (
	"net"
	"net/http"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/hub/resource"
	"github.com/agberohq/agbero/internal/pkg/tunnel"
	"github.com/olekukonko/errors"
)

var hopHeaders = []string{
	def.HeaderKeyConnection,
	def.HeaderKeepAlive,
	def.HeaderProxyAuthenticate,
	def.HeaderProxyAuthorization,
	def.HeaderTE,
	def.HeaderTrailers,
	def.HeaderTransferEncoding,
	def.HeaderKeyUpgrade,
}

type ConfigProxy struct {
	Strategy string
	Keys     []string
	Timeout  time.Duration
	Fallback http.Handler
}

// Validate checks that ConfigProxy fields are within acceptable bounds.
func (c ConfigProxy) Validate() error {
	if c.Timeout < 0 {
		return errors.New("timeout cannot be negative")
	}
	return nil
}

type ConfigBackend struct {
	Server   alaye.Server
	Route    *alaye.Route
	Domains  []string
	Fallback http.Handler
	Resource *resource.Resource
	// TunnelPool routes outbound connections through SOCKS5 when non-nil.
	// Nil means direct connection (default behaviour).
	TunnelPool *tunnel.Pool
}

// Validate checks that the backend address and resource manager are present.
func (c ConfigBackend) Validate() error {
	if c.Server.Address == "" {
		return errors.New("server address required")
	}
	if c.Resource == nil {
		return errors.New("resource manager required")
	}
	if c.Resource.Metrics == nil {
		return errors.New("metrics registry required")
	}
	if c.Resource.Health == nil {
		return errors.New("health registry required")
	}
	return nil
}

type ipRule struct {
	ip   net.IP
	cidr *net.IPNet
}
