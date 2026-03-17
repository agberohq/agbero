package alaye

import (
	"fmt"
	"time"
)

// NewEphemeralGlobal creates a minimal in-memory Global config for ephemeral/CLI use.
// It sets sensible defaults without requiring a config file on disk.
func NewEphemeralGlobal(port int, https bool) *Global {
	bindAddr := fmt.Sprintf(":%d", port)

	g := &Global{
		Version:     2,
		Development: true,
		Timeouts: Timeout{
			Enabled:    Active,
			Read:       Duration(10 * time.Second),
			Write:      Duration(30 * time.Second),
			Idle:       Duration(60 * time.Second),
			ReadHeader: Duration(5 * time.Second),
		},
		Logging: Logging{
			Enabled: Active,
			Level:   "info",
		},
		General: General{
			MaxHeaderBytes: DefaultMaxHeaderBytes,
		},
		Admin:    Admin{Enabled: Inactive},
		Gossip:   Gossip{Enabled: Inactive},
		Security: Security{Enabled: Inactive},
		Fallback: Fallback{Enabled: Inactive},
	}

	if https {
		g.Bind.HTTPS = []string{bindAddr}
	} else {
		g.Bind.HTTP = []string{bindAddr}
	}

	return g
}

// NewStaticHost creates a Host config for a single domain pointing to a static
// target — either a proxy backend address or a local filesystem root.
func NewStaticHost(domain string, target Address, isProxy bool) *Host {
	h := &Host{
		Domains: []string{domain},
		Routes:  make([]Route, 1),
		TLS: TLS{
			Mode: ModeLocalAuto,
		},
	}

	h.Headers.Enabled = Unknown

	route := Route{
		Enabled: Active,
		Path:    "/",
	}

	if isProxy {
		route.Backends = Backend{
			Enabled:  Active,
			Strategy: StrategyRoundRobin,
			Servers: []Server{
				{
					Address: target,
					Weight:  1,
				},
			},
		}
		route.Web.Enabled = Inactive
	} else {
		route.Web = Web{
			Enabled: Active,
			Root:    WebRoot(target),
			Listing: true,
			Index:   "index.html",
		}
		route.Backends.Enabled = Inactive
	}

	h.Routes[0] = route
	return h
}
