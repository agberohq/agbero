package alaye

import (
	"net"
	"net/url"

	"github.com/olekukonko/errors"
)

// rejectPrivateURL resolves the host in rawURL and returns an error if any
// resolved address falls within RFC-1918, loopback, or link-local ranges.
// DNS resolution is attempted first; if that fails the host is parsed as a
// literal IP. This provides config-time SSRF protection — a second runtime
// check in the middleware handles TOCTOU cases where DNS changes after startup.
func rejectPrivateURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return errors.Newf("invalid URL: %w", err)
	}

	host := u.Hostname()
	if host == "" {
		return errors.New("URL has no host")
	}

	addrs, err := net.LookupHost(host)
	if err != nil {
		// Treat unresolvable hosts as potentially safe at config time;
		// the runtime check in the middleware will catch them on first use.
		if ip := net.ParseIP(host); ip != nil {
			addrs = []string{ip.String()}
		} else {
			return nil
		}
	}

	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if isPrivateIP(ip) {
			return errors.Newf("host %q resolves to private/loopback address %s", host, ip)
		}
	}
	return nil
}

// isPrivateIP reports whether ip falls within a private, loopback, or
// link-local range that must not be reachable from a forward_auth target
// unless allow_private = true is explicitly set.
func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	private := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",
		"169.254.0.0/16",
		"fc00::/7",
		"fe80::/10",
	}

	for _, cidr := range private {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
