package woos

import (
	"net"
	"strings"

	"github.com/agberohq/agbero/internal/core/def"
)

// IsLocalContext returns true if the host is either loopback or a private LAN IP.
func IsLocalContext(host string) bool {
	return IsLocalhost(host) || IsLocalArea(host)
}

// IsLocalhost determines if a hostname implies the machine itself.
func IsLocalhost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == def.LocalhostExact {
		return true
	}
	if strings.HasSuffix(host, def.LocalhostSuffixDotLocalhost) {
		return true
	}
	if strings.HasSuffix(host, def.LocalhostSuffixDotLocal) {
		return true
	}
	if strings.HasSuffix(host, def.LocalhostSuffixDotTest) {
		return true
	}

	if strings.HasSuffix(host, def.LocalhostSuffixDotInternal) { // ADD THIS
		return true
	}

	// Check loopback IPs
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// IsLocalArea determines if a host is a Private Network IP (RFC 1918).
func IsLocalArea(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() && !ip.IsLoopback()
}

// Port extracts the port cleanly from a network address.
// Safely handles IPv6 brackets and falls back to the default HTTPS port.
func Port(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return def.DefaultHTTPSPortInt
	}
	return port
}
