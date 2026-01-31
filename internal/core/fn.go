package core

import (
	"net"
	"strings"
	"time"
)

const (
	SchemeHTTP                  = "http@"
	SchemeHTTPS                 = "https@"
	LocalhostExact              = "localhost"
	LocalhostSuffixDotLocal     = ".local"
	LocalhostSuffixDotLocalhost = ".localhost"
	LocalhostSuffixDotTest      = ".test"

	LeftBracket  = "["
	RightBracket = "]"
	Dot          = "."
)

func NormalizeHost(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(hostport)
}

func ServerKey(addr string, tls bool) string {
	if tls {
		return SchemeHTTPS + addr
	}
	return SchemeHTTP + addr
}

func IsServerKeyTLS(key string) bool {
	return strings.HasPrefix(key, SchemeHTTPS)
}

func NormalizeSubject(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, Dot)
	s = strings.ToLower(s)

	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}

	s = strings.TrimPrefix(s, LeftBracket)
	s = strings.TrimSuffix(s, RightBracket)

	return s
}

func Or[T comparable](a ...T) T {
	var zero T
	for _, v := range a {
		if v != zero {
			return v
		}
	}
	return zero
}

// Debounce returns a function that calls f only after delay since last call
func Debounce(delay time.Duration, f func()) func() {
	var timer *time.Timer
	return func() {
		if timer != nil {
			timer.Stop()
		}
		timer = time.AfterFunc(delay, f)
	}
}

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
