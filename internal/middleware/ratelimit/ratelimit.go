package ratelimit

import (
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/middleware/clientip"
	"github.com/cespare/xxhash/v2"
	"golang.org/x/time/rate"
)

type RatePolicy struct {
	Requests int
	Window   time.Duration
	Burst    int
	KeySpec  string // "ip", "header:Key", "cookie:Name"
}

func (p RatePolicy) limiter() *rate.Limiter {
	if p.Requests <= 0 {
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
	lastSeen int64
}

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
	stopCh     chan struct{}
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
		if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			next.ServeHTTP(w, r)
			return
		}

		bucketName, pol, ok := rl.policy(r)
		if !ok || pol.Requests <= 0 {
			next.ServeHTTP(w, r)
			return
		}

		key := ""
		spec := strings.ToLower(pol.KeySpec)

		if strings.HasPrefix(spec, "header:") {
			headerName := strings.TrimPrefix(spec, "header:")
			key = r.Header.Get(headerName)
		} else if strings.HasPrefix(spec, "cookie:") {
			cookieName := strings.TrimPrefix(spec, "cookie:")
			if c, err := r.Cookie(cookieName); err == nil {
				key = c.Value
			}
		} else {
			// Default to IP
			key = clientip.ClientIP(r)
		}

		if key == "" {
			// If key strategy failed (missing header/cookie), we typically
			// shouldn't block, or we should fallback to IP.
			// Here we fallback to IP to ensure protection.
			key = clientip.ClientIP(r)
		}

		fullKey := bucketName + ":" + key

		now := time.Now().UnixNano()
		idx := xxhash.Sum64String(fullKey) % uint64(len(rl.shards))
		sh := &rl.shards[idx]

		sh.mu.Lock()
		e := sh.m[fullKey]
		if e == nil {
			if rl.size.Load() >= rl.maxEntries {
				rl.pruneShardLocked(sh, now)
			}
			e = &ipEntry{lim: pol.limiter(), lastSeen: now}
			sh.m[fullKey] = e
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
