package zulu

import (
	"net"
	"net/http"
	"strings"
)

var (
	IP = NewIP()
)

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

func extractIP(addr string) string {
	idx := strings.LastIndexByte(addr, ':')
	if idx == -1 {
		return addr
	}
	ip := addr[:idx]
	if len(ip) > 0 && ip[0] == '[' && ip[len(ip)-1] == ']' {
		return ip[1 : len(ip)-1]
	}
	return ip
}

func (m *IPManager) ClientIP(r *http.Request) string {
	remoteIP := extractIP(r.RemoteAddr)

	if len(m.trusted) == 0 {
		return remoteIP
	}

	ip := net.ParseIP(remoteIP)
	if ip == nil {
		return remoteIP
	}

	isTrusted := false
	for _, cidr := range m.trusted {
		if cidr.Contains(ip) {
			isTrusted = true
			break
		}
	}

	if isTrusted {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
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
