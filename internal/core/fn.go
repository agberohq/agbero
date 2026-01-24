package core

import (
	"net"
	"strings"
	"time"
)

func NormalizeHost(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(hostport)
}

func ServerKey(addr string, tls bool) string {
	if tls {
		return "https@" + addr
	}
	return "http@" + addr
}

func IsServerKeyTLS(key string) bool {
	return strings.HasPrefix(key, "https@")
}

func NormalizeSubject(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".")
	s = strings.ToLower(s)

	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}

	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")

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
	if host == "localhost" {
		return true
	}
	if strings.HasSuffix(host, ".localhost") {
		return true
	}
	if strings.HasSuffix(host, ".local") {
		return true
	}
	if strings.HasSuffix(host, ".test") {
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
