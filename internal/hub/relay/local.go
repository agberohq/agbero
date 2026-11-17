package relay

import (
	"net"
	"net/url"
	"strings"

	"github.com/agberohq/agbero/internal/core/alaye"
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
			local = "https://127.0.0.1:443"
		case has80:
			local = "http://127.0.0.1:80"
		case hasOther != "":
			local = "http://127.0.0.1:" + hasOther
		}
	}
	if local != "" {
		if u, err := url.Parse(local); err == nil && u.Scheme == "https" {
			host := u.Hostname()
			if host == "127.0.0.1" || host == "::1" || host == "localhost" {
				insecure = true
			}
		}
	}
	return local, sni, insecure
}
