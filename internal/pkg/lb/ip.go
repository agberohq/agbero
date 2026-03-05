package lb

import (
	"net"
	"net/http"
	"strings"

	"github.com/olekukonko/mappo"
)

// ipCache caches extracted IPs to avoid repeated parsing overhead.
var ipCache = mappo.NewLRU[string, string](4096)

// ClientIP extracts the client IP with advanced proxy support.
// Supports X-Forwarded-For, X-Real-IP, Forwarded (RFC 7239), and falls back to RemoteAddr.
func ClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}

	cacheKey := r.RemoteAddr + "|" + r.Header.Get("X-Forwarded-For") + "|" +
		r.Header.Get("X-Real-IP") + "|" + r.Header.Get("Forwarded")

	if cached, ok := ipCache.Get(cacheKey); ok {
		return cached
	}

	ip := extractClientIP(r)
	if ip != "" {
		ipCache.Set(cacheKey, ip)
	}
	return ip
}

func extractClientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		if idx := strings.Index(fwd, ","); idx != -1 {
			fwd = fwd[:idx]
		}
		if ip := strings.TrimSpace(fwd); ip != "" {
			return normalizeIP(ip)
		}
	}

	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return normalizeIP(strings.TrimSpace(realIP))
	}

	if fwd := r.Header.Get("Forwarded"); fwd != "" {
		if ip := parseForwardedHeader(fwd); ip != "" {
			return ip
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func normalizeIP(ip string) string {
	ip = strings.TrimSpace(ip)

	if strings.HasPrefix(ip, "[") {
		if end := strings.Index(ip, "]"); end > 0 {
			ip = ip[1:end]
		}
		return ip
	}

	if host, _, err := net.SplitHostPort(ip); err == nil {
		return host
	}

	return ip
}

func parseForwardedHeader(fwd string) string {
	// RFC 7239: entries are comma-separated; params within entry are semicolon-separated
	for _, entry := range strings.Split(fwd, ",") {
		entry = strings.TrimSpace(entry)
		// Find the for= parameter (case-insensitive)
		lower := strings.ToLower(entry)
		if strings.HasPrefix(lower, "for=") {
			val := strings.TrimSpace(entry[4:]) // skip "for="
			val = strings.Trim(val, "\"")
			// Handle bracketed IPv6 addresses
			if strings.HasPrefix(val, "[") {
				if end := strings.Index(val, "]"); end > 0 {
					return val[1:end]
				}
			}
			return normalizeIP(val)
		}
	}
	return ""
}
