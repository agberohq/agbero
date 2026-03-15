package alaye

import (
	"fmt"
	"net/url"
	"strings"
)

// Address represents a versatile network address (e.g., :9090, 192.168.0.1, https://domain.com)
type Address string

// String returns the raw address string.
func (a Address) String() string {
	return string(a)
}

// Scheme extracts the protocol scheme if present (e.g., "http", "https", "tcp", "unix").
func (a Address) Scheme() string {
	s := string(a)
	if idx := strings.Index(s, "://"); idx != -1 {
		return strings.ToLower(s[:idx])
	}
	if strings.HasPrefix(s, "unix:") {
		return "unix"
	}
	return ""
}

// HostPort extracts the host and port, stripping the scheme.
func (a Address) HostPort() string {
	s := string(a)
	if idx := strings.Index(s, "://"); idx != -1 {
		s = s[idx+3:]
	}
	return s
}

// URL parses the address into a standard url.URL.
// If no scheme is provided, it defaults to "http://" to ensure successful parsing of domains/IPs.
func (a Address) URL() (*url.URL, error) {
	s := string(a)
	if !strings.Contains(s, "://") && !strings.HasPrefix(s, "unix:") {
		s = "http://" + s
	}
	return url.Parse(s)
}

// Validate ensures the address is not empty.
func (a Address) Validate() error {
	if string(a) == "" {
		return fmt.Errorf("address cannot be empty")
	}
	return nil
}
