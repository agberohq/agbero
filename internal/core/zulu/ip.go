package zulu

import (
	"net"
	"net/http"
	"strings"
)

var (
	IP = NewIP()
)

// IPManager handles trusted proxy logic efficiently.
type IPManager struct {
	trusted []*net.IPNet
}

func NewIP(trustedCIDRs ...string) *IPManager {
	return NewIPManager(trustedCIDRs)
}

func NewIPManager(trustedCIDRs []string) *IPManager {
	var cidrs []*net.IPNet
	for _, t := range trustedCIDRs {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(t); err == nil {
			cidrs = append(cidrs, n)
			continue
		}
		if ip := net.ParseIP(t); ip != nil {
			mask := net.CIDRMask(32, 32)
			if ip.To4() == nil {
				mask = net.CIDRMask(128, 128)
			}
			cidrs = append(cidrs, &net.IPNet{IP: ip, Mask: mask})
		}
	}
	return &IPManager{trusted: cidrs}
}

func (m *IPManager) ClientIP(r *http.Request) string {
	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteIP = r.RemoteAddr
	}

	// If no trusted proxies are configured, return the direct peer
	if len(m.trusted) == 0 {
		return remoteIP
	}

	ip := net.ParseIP(remoteIP)
	if ip == nil {
		return remoteIP
	}

	// Check if immediate peer is trusted
	isTrusted := false
	for _, cidr := range m.trusted {
		if cidr.Contains(ip) {
			isTrusted = true
			break
		}
	}

	if isTrusted {
		// Parse X-Forwarded-For
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Work backwards through the list
			parts := strings.Split(xff, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				p := strings.TrimSpace(parts[i])
				if p == "" {
					continue
				}
				parsed := net.ParseIP(p)
				if parsed == nil {
					continue
				}

				// If this IP is ALSO trusted, keep going back.
				// The first NON-trusted IP is the real client.
				isHopTrusted := false
				for _, cidr := range m.trusted {
					if cidr.Contains(parsed) {
						isHopTrusted = true
						break
					}
				}

				if !isHopTrusted {
					return p
				}
			}
		}

		if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
			return xrip
		}
	}

	return remoteIP
}
