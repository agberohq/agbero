package woos

import (
	"net"
	"strings"
)

// IsLocalhost determines if a hostname implies local development
func IsLocalhost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == LocalhostExact {
		return true
	}
	if strings.HasSuffix(host, LocalhostSuffixDotLocalhost) {
		return true
	}
	if strings.HasSuffix(host, LocalhostSuffixDotLocal) {
		return true
	}
	if strings.HasSuffix(host, LocalhostSuffixDotTest) {
		return true
	}
	// Check loopback IPs
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() {
			return true
		}
	}
	return false
}
