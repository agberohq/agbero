package relay

import (
	"net"
	"net/url"
	"strings"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
)

// ResolveLocal derives the agent's local Agbero target from the host config.
// Explicit agent values win. Loopback HTTPS targets use the host's first domain
// as SNI and skip verification because they are the same local installation.
func ResolveLocal(h *alaye.Host, a alaye.Agent) (local, sni string, insecure bool) {
	local = strings.TrimSpace(a.Local)
	sni = strings.TrimSpace(a.LocalSNI)
	insecure = a.LocalInsecure
	if sni == "" && len(h.Domains) > 0 {
		sni = h.Domains[0]
	}
	if local == "" {
		has443, has80, hasOther := false, false, ""
		for _, bind := range h.Bind {
			_, port, err := net.SplitHostPort(bind)
			if err != nil {
				continue
			}
			switch port {
			case "443":
				has443 = true
			case "80":
				has80 = true
			default:
				if hasOther == "" {
					hasOther = port
				}
			}
		}
		switch {
		case has443:
			local = def.Https + "://" + def.IPv4LoopbackSAN + ":" + def.RelayHTTPSPort
		case has80:
			local = def.Http + "://" + def.IPv4LoopbackSAN + ":" + def.RelayHTTPPort
		case hasOther != "":
			local = def.Http + "://" + def.IPv4LoopbackSAN + ":" + hasOther
		}
	}
	if local != "" {
		if u, err := url.Parse(local); err == nil && u.Scheme == def.Https {
			host := u.Hostname()
			if host == def.IPv4LoopbackSAN || host == def.IPv6LoopbackSAN || host == def.Localhost {
				insecure = true
			}
		}
	}
	return local, sni, insecure
}
