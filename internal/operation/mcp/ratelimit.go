package mcp

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RateLimit returns a per-token/per-IP fixed-window limiter. spec is the
// validated mcp.rate_limit form (60/m, 10/s, 1000/h). It runs after auth so
// the token subject is available; the request IP is also part of the key.
func RateLimit(spec string) func(http.Handler) http.Handler {
	limit, window, ok := parseRateLimit(spec)
	if !ok || limit <= 0 || window <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	var mu sync.Mutex
	type bucket struct {
		start time.Time
		count int
	}
	buckets := make(map[string]*bucket)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := rateKey(r)
			now := time.Now()
			mu.Lock()
			b := buckets[key]
			if b == nil || now.Sub(b.start) >= window {
				b = &bucket{start: now}
				buckets[key] = b
			}
			b.count++
			allowed := b.count <= limit
			// Opportunistic cleanup so a long-lived process cannot grow the map
			// without bound.
			if len(buckets) > 4096 {
				for k, v := range buckets {
					if now.Sub(v.start) >= window {
						delete(buckets, k)
					}
				}
			}
			mu.Unlock()
			if !allowed {
				w.Header().Set("Retry-After", strconv.Itoa(int(window.Seconds())))
				http.Error(w, `{"error":"rate_limited"}`, http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func rateKey(r *http.Request) string {
	subject := "anonymous"
	if c := ClaimsFromContext(r.Context()); c != nil && c.Subject != "" {
		subject = c.Subject
	}
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ip = host
	}
	return subject + "|" + ip
}

func parseRateLimit(spec string) (int, time.Duration, bool) {
	spec = strings.TrimSpace(strings.ToLower(spec))
	if spec == "" {
		return 0, 0, false
	}
	parts := strings.SplitN(spec, "/", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	n, err := strconv.Atoi(parts[0])
	if err != nil || n <= 0 {
		return 0, 0, false
	}
	var window time.Duration
	switch parts[1] {
	case "s":
		window = time.Second
	case "m":
		window = time.Minute
	case "h":
		window = time.Hour
	default:
		return 0, 0, false
	}
	return n, window, true
}
