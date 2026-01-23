package ratelimit

import (
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/middleware/clientip"
	"golang.org/x/time/rate"
)

type RatePolicy struct {
	// Requests per window (e.g. 60 per 1m)
	Requests int
	Window   time.Duration
	// Burst tokens (usually same as Requests or smaller)
	Burst int
}

func (p RatePolicy) limiter() *rate.Limiter {
	if p.Requests <= 0 {
		// "disabled"
		return rate.NewLimiter(rate.Inf, 0)
	}
	if p.Window <= 0 {
		p.Window = time.Second
	}
	if p.Burst <= 0 {
		p.Burst = p.Requests
	}
	limit := rate.Limit(float64(p.Requests) / p.Window.Seconds())
	return rate.NewLimiter(limit, p.Burst)
}

type ipEntry struct {
	lim      *rate.Limiter
	lastSeen int64 // unix nano
}

// sharded map for speed and reduced lock contention
type rateShard struct {
	mu sync.Mutex
	m  map[string]*ipEntry
}

type RateLimiter struct {
	shards     []rateShard
	policy     func(r *http.Request) (bucket string, pol RatePolicy, ok bool)
	ttl        time.Duration
	maxEntries int64
	size       atomic.Int64

	stopCh chan struct{}
}

func NewRateLimiter(ttl time.Duration, maxEntries int64, policy func(r *http.Request) (bucket string, pol RatePolicy, ok bool)) *RateLimiter {
	const shardCount = 64

	rl := &RateLimiter{
		shards:     make([]rateShard, shardCount),
		policy:     policy,
		ttl:        ttl,
		maxEntries: maxEntries,
		stopCh:     make(chan struct{}),
	}

	for i := range rl.shards {
		rl.shards[i].m = make(map[string]*ipEntry)
	}

	if rl.ttl <= 0 {
		rl.ttl = 30 * time.Minute
	}
	if rl.maxEntries <= 0 {
		rl.maxEntries = 100_000
	}

	go rl.sweeper()
	return rl
}

func (rl *RateLimiter) Close() { close(rl.stopCh) }

func (rl *RateLimiter) Handler(next http.Handler) http.Handler {
	if rl == nil || rl.policy == nil {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always allow ACME challenges
		if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			next.ServeHTTP(w, r)
			return
		}

		_, pol, ok := rl.policy(r)
		if !ok || pol.Requests <= 0 {
			next.ServeHTTP(w, r)
			return
		}

		ip := clientip.ClientIP(r)
		if ip == "" {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		now := time.Now().UnixNano()
		key := ip // per-IP. (If you want per-host too: key = host + "|" + ip)

		sh := &rl.shards[fnv1a(key)%uint64(len(rl.shards))]
		sh.mu.Lock()
		e := sh.m[key]
		if e == nil {
			// memory safety: if we are way over max, do a quick local prune
			if rl.size.Load() >= rl.maxEntries {
				rl.pruneShardLocked(sh, now)
				// still too big? fail-closed or allow? I recommend fail-closed for abuse endpoints,
				// but for general traffic you may choose to allow.
				// We'll keep allowing inserts, but the sweeper will prune aggressively.
			}

			e = &ipEntry{lim: pol.limiter(), lastSeen: now}
			sh.m[key] = e
			rl.size.Add(1)
		} else {
			e.lastSeen = now
		}

		allowed := e.lim.Allow()
		sh.mu.Unlock()

		if !allowed {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) sweeper() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-rl.stopCh:
			return
		case <-ticker.C:
			now := time.Now().UnixNano()
			for i := range rl.shards {
				sh := &rl.shards[i]
				sh.mu.Lock()
				rl.pruneShardLocked(sh, now)
				sh.mu.Unlock()
			}
		}
	}
}

func (rl *RateLimiter) pruneShardLocked(sh *rateShard, now int64) {
	if len(sh.m) == 0 {
		return
	}
	cutoff := now - rl.ttl.Nanoseconds()
	for k, e := range sh.m {
		if e == nil || e.lastSeen < cutoff {
			delete(sh.m, k)
			rl.size.Add(-1)
		}
	}
}

func fnv1a(s string) uint64 {
	var h uint64 = 1469598103934665603
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}
