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
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPCtxKey{}, ip)
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
	return &IPMiddleware{trusted: cidrs}
}

func (m *IPMiddleware) Handler(next http.Handler) http.Handler {
	if m == nil || len(m.trusted) == 0 {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peerIP := directPeerIP(r.RemoteAddr)
		trusted := m.isTrusted(peerIP)

		ip := peerIP
		if trusted {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				if candidate := clientFromXFF(xff, m.trusted); candidate != "" {
					ip = candidate
				}
			} else if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
				if parsed := net.ParseIP(xrip); parsed != nil {
					ip = xrip
				}
			}
		}

		ctx := WithClientIP(r.Context(), ip)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *IPMiddleware) isTrusted(ip string) bool {
	if m == nil {
		return false
	}
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
	parts := strings.Split(xff, ",")
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
	for i := range parts {
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
