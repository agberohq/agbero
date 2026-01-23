package core

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"strings"
	"sync/atomic"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
)

var fallbackRand uint64

func RouteKey(route *woos.Route) string {
	var sb strings.Builder
	sb.Grow(256)

	sb.WriteString("p=")
	sb.WriteString(route.Path)
	sb.WriteString("|s=")
	sb.WriteString(strings.ToLower(strings.TrimSpace(route.LBStrategy)))

	sb.WriteString("|b=")
	for i, b := range route.Backends {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(strings.TrimSpace(b))
	}

	sb.WriteString("|sp=")
	for i, p := range route.StripPrefixes {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(p)
	}

	// High Availability
	if route.HealthCheck != nil {
		sb.WriteString("|hc=")
		sb.WriteString(route.HealthCheck.Path)
		sb.WriteString(route.HealthCheck.Interval)
		sb.WriteString(route.HealthCheck.Timeout)
	}

	if route.CircuitBreaker != nil {
		sb.WriteString("|cb=")
		sb.WriteByte(byte(route.CircuitBreaker.Threshold))
	}

	if route.Timeouts != nil {
		sb.WriteString("|to=")
		sb.WriteString(route.Timeouts.Request)
	}

	// Middlewares
	if route.Compression {
		sb.WriteString("|gz=1")
	}

	if route.Headers != nil {
		sb.WriteString("|hd=1")
		// Optimization: We assume if the pointer is non-nil, headers are active.
		// For perfect cache busting on content change, we would need to hash the map keys/values.
		// Given the frequency of config changes, this simple check is usually sufficient
		// unless you modify header values in-place without changing other config.
	}

	if route.BasicAuth != nil {
		sb.WriteString("|ba=")
		sb.WriteByte(byte(len(route.BasicAuth.Users)))
	}

	if route.ForwardAuth != nil {
		sb.WriteString("|fa=")
		sb.WriteString(route.ForwardAuth.URL)
	}

	return sb.String()
}

func PathMatch(requestPath, pattern string) bool {
	if pattern == "*" {
		return true
	}

	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(requestPath, prefix)
	}

	return requestPath == pattern
}

// ParseBind supports formats like:
//
//	":80 :443"
//	"0.0.0.0:80 0.0.0.0:443"
//	"[::]:80 [::]:443"
func ParseBind(bind string) []string {
	bind = strings.TrimSpace(bind)
	if bind == "" {
		return nil
	}
	parts := strings.Fields(bind)

	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func NormalizeHost(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(hostport)
}

func IsHTTPSBind(addr string) bool {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return port == "443"
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

func randUint64() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err == nil {
		return binary.LittleEndian.Uint64(b[:])
	}
	return uint64(atomic.AddUint64(&fallbackRand, 1))
}
