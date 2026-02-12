package clientip

import (
	"context"
	"net"
	"net/http"
	"strings"
)

type clientIPCtxKey struct{}

func ClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if v := r.Context().Value(clientIPCtxKey{}); v != nil {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	// fallback: parse r.RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

type IPMiddleware struct {
	trusted []*net.IPNet
}

func NewIPMiddleware(trusted []string) *IPMiddleware {
	var cidrs []*net.IPNet

	for _, t := range trusted {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}

		// CIDR
		if _, n, err := net.ParseCIDR(t); err == nil {
			cidrs = append(cidrs, n)
			continue
		}

		// Single IP
		if ip := net.ParseIP(t); ip != nil {
			mask := net.CIDRMask(32, 32)
			if ip.To4() == nil {
				mask = net.CIDRMask(128, 128)
			}
			cidrs = append(cidrs, &net.IPNet{IP: ip, Mask: mask})
		}
	}

	return &IPMiddleware{trusted: cidrs}
}

func (m *IPMiddleware) Handler(next http.Handler) http.Handler {
	if m == nil {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peerIP := directPeerIP(r.RemoteAddr)
		trusted := m.isTrusted(peerIP)

		ip := peerIP
		if trusted {
			// Prefer XFF if present; walk from right-to-left and strip trusted proxies.
			// This prevents spoofing in multi-proxy chains.
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				if candidate := clientFromXFF(xff, m.trusted); candidate != "" {
					ip = candidate
				}
			} else if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
				if parsed := net.ParseIP(xrip); parsed != nil {
					// Only use X-Real-IP if it's NOT a trusted proxy itself,
					// or if we decide to trust the last hop's assertion.
					// Most implementations treat X-Real-IP as the immediate client
					// known to the proxy.
					ip = xrip
				}
			}
		}

		ctx := context.WithValue(r.Context(), clientIPCtxKey{}, ip)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *IPMiddleware) isTrusted(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range m.trusted {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

func directPeerIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil && host != "" {
		return host
	}
	return remoteAddr
}

func clientFromXFF(xff string, trusted []*net.IPNet) string {
	// XFF format: client, proxy1, proxy2
	parts := strings.Split(xff, ",")
	// Walk from right to left, remove trusted proxies, first non-trusted is client.
	for i := len(parts) - 1; i >= 0; i-- {
		p := strings.TrimSpace(parts[i])
		if p == "" {
			continue
		}
		ip := net.ParseIP(p)
		if ip == nil {
			continue
		}
		if isInCIDRs(ip, trusted) {
			continue
		}
		return p
	}

	// If all are trusted (or none), fall back to first valid IP
	for i := 0; i < len(parts); i++ {
		p := strings.TrimSpace(parts[i])
		if net.ParseIP(p) != nil {
			return p
		}
	}
	return ""
}

func isInCIDRs(ip net.IP, cidrs []*net.IPNet) bool {
	for _, n := range cidrs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
