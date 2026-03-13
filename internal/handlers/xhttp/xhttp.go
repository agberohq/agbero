package xhttp

import (
	"net"
	"net/http"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/resource"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/ll"
)

var hopHeaders = []string{
	woos.HeaderKeyConnection,
	woos.HeaderKeepAlive,
	woos.HeaderProxyAuthenticate,
	woos.HeaderProxyAuthorization,
	woos.HeaderTE,
	woos.HeaderTrailers,
	woos.HeaderTransferEncoding,
	woos.HeaderKeyUpgrade,
}

type ConfigProxy struct {
	Strategy string
	Keys     []string
	Timeout  time.Duration
	Fallback http.Handler
}

func (c ConfigProxy) Validate() error {
	if c.Timeout < 0 {
		return errors.New("timeout cannot be negative")
	}
	// Strategy and Keys are optional; no validation needed
	return nil
}

type ConfigBackend struct {
	Server   alaye.Server
	Route    *alaye.Route
	Domains  []string
	Logger   *ll.Logger
	Fallback http.Handler
	Resource *resource.Manager
}

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
