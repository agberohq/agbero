package woos

import (
	"fmt"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
)

// NewEphemeralGlobal creates a minimal in-memory Global config for ephemeral/CLI use.
// It sets sensible defaults without requiring a config file on disk.
func NewEphemeralGlobal(port int, https bool) *alaye.Global {
	bindAddr := fmt.Sprintf(":%d", port)

	g := &alaye.Global{
		Version:     2,
		Development: true,
		Timeouts: alaye.Timeout{
			Enabled:    alaye.Active,
			Read:       alaye.Duration(10 * time.Second),
			Write:      alaye.Duration(30 * time.Second),
			Idle:       alaye.Duration(60 * time.Second),
			ReadHeader: alaye.Duration(5 * time.Second),
		},
		Logging: alaye.Logging{
			Enabled: alaye.Active,
			Level:   "info",
		},
		General: alaye.General{
			MaxHeaderBytes: alaye.DefaultMaxHeaderBytes,
		},
		Admin:    alaye.Admin{Enabled: alaye.Inactive},
		Gossip:   alaye.Gossip{Enabled: alaye.Inactive},
		Security: alaye.Security{Enabled: alaye.Inactive},
		Fallback: alaye.Fallback{Enabled: alaye.Inactive},
	}

	if https {
		g.Bind.HTTPS = []string{bindAddr}
	} else {
		g.Bind.HTTP = []string{bindAddr}
	}

	return g
}

type Static struct {
	Domain   string
	Target   alaye.Address
	IsProxy  bool
	Markdown bool
	SPA      bool
	PHP      string
}

// NewStaticHost creates a Host config for a single domain pointing to a static
// target — either a proxy backend address or a local filesystem root.
// When markdown is true, .md files are rendered as HTML instead of served raw.
func NewStaticHost(c Static) *alaye.Host {
	h := &alaye.Host{
		Domains: []string{c.Domain},
		Routes:  make([]alaye.Route, 1),
		TLS: alaye.TLS{
			Mode: alaye.ModeLocalAuto,
		},
	}

	h.Headers.Enabled = alaye.Unknown

	route := alaye.Route{
		Enabled: alaye.Active,
		Path:    "/",
	}

	if c.IsProxy {
		route.Backends = alaye.Backend{
			Enabled:  alaye.Active,
			Strategy: alaye.StrategyRoundRobin,
			Servers: []alaye.Server{
				{
					Address: c.Target,
					Weight:  1,
				},
			},
		}
		route.Web.Enabled = alaye.Inactive
	} else {
		markdownToggle := alaye.Inactive
		if c.Markdown {
			markdownToggle = alaye.Active
		}

		phpToggle := alaye.Inactive
		if c.PHP != "" {
			markdownToggle = alaye.Active
		}

		route.Web = alaye.Web{
			Enabled: alaye.Active,
			Root:    alaye.WebRoot(c.Target),
			Listing: alaye.NewEnabled(true),
			Index:   []string{"index.html"},
			SPA:     alaye.NewEnabled(c.SPA),
			Markdown: alaye.Markdown{
				Enabled: markdownToggle,
				View:    "normal",
			},
			PHP: alaye.PHP{
				Enabled: phpToggle,
				Address: c.PHP,
			},
		}
		route.Backends.Enabled = alaye.Inactive
	}

	h.Routes[0] = route
	return h
}
