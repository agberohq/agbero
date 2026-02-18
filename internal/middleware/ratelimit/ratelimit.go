package ratelimit

import (
	"net/http"
	"path"
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
	lastSeen atomic.Int64 // atomic to avoid lock contention on updates
}

type rateShard struct {
	mu sync.RWMutex // RWMutex for better read concurrency
	m  map[string]*ipEntry
}

type RateLimiter struct {
	shards     []rateShard
	policy     func(r *http.Request) (bucket string, pol RatePolicy, ok bool)
	ttl        int64 // store as nanoseconds to avoid conversion
	maxEntries int64
	size       atomic.Int64
	stopCh     chan struct{}
}

func NewRateLimiter(ttl time.Duration, maxEntries int64, policy func(r *http.Request) (bucket string, pol RatePolicy, ok bool)) *RateLimiter {
	const shardCount = 256 // Increased from 64 for less contention
	rl := &RateLimiter{
		shards:     make([]rateShard, shardCount),
		policy:     policy,
		ttl:        ttl.Nanoseconds(),
		maxEntries: maxEntries,
		stopCh:     make(chan struct{}),
	}
	for i := range rl.shards {
		rl.shards[i].m = make(map[string]*ipEntry)
	}
	if rl.ttl <= 0 {
		rl.ttl = 30 * time.Minute.Nanoseconds()
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
		cleanPath := path.Clean(r.URL.Path)

		if strings.HasPrefix(cleanPath, "/.well-known/acme-challenge/") {
			next.ServeHTTP(w, r)
			return
		}

		// Avoid copying the request - pass URL directly if needed
		bucketName, pol, ok := rl.policy(r)
		if !ok || pol.Requests <= 0 {
			next.ServeHTTP(w, r)
			return
		}

		key := rl.extractKey(r, pol.KeySpec)
		fullKey := bucketName + ":" + key

		// Fast path: try read lock first
		idx := xxhash.Sum64String(fullKey) % uint64(len(rl.shards))
		sh := &rl.shards[idx]

		sh.mu.RLock()
		e := sh.m[fullKey]
		if e != nil {
			// Update lastSeen atomically without write lock
			e.lastSeen.Store(time.Now().UnixNano())
			allowed := e.lim.Allow()
			sh.mu.RUnlock()
			if !allowed {
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		sh.mu.RUnlock()

		// Slow path: need to create entry
		sh.mu.Lock()
		// Double-check after acquiring write lock
		e = sh.m[fullKey]
		if e != nil {
			e.lastSeen.Store(time.Now().UnixNano())
			allowed := e.lim.Allow()
			sh.mu.Unlock()
			if !allowed {
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// Check size limit with relaxed check (may exceed slightly)
		if rl.size.Load() >= rl.maxEntries {
			sh.mu.Unlock()
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		e = &ipEntry{lim: pol.limiter()}
		e.lastSeen.Store(time.Now().UnixNano())
		sh.m[fullKey] = e
		rl.size.Add(1)
		allowed := e.lim.Allow()
		sh.mu.Unlock()

		if !allowed {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) extractKey(r *http.Request, keySpec string) string {
	// Fast path: empty spec = IP
	if keySpec == "" {
		return clientip.ClientIP(r)
	}

	// Avoid ToLower - use case-sensitive prefix match
	if len(keySpec) > 7 && keySpec[:7] == "header:" {
		return r.Header.Get(keySpec[7:])
	}
	if len(keySpec) > 7 && keySpec[:7] == "cookie:" {
		if c, err := r.Cookie(keySpec[7:]); err == nil {
			return c.Value
		}
	}

	return clientip.ClientIP(r)
}

func (rl *RateLimiter) sweeper() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-rl.stopCh:
			for i := range rl.shards {
				sh := &rl.shards[i]
				sh.mu.Lock()
				sh.m = make(map[string]*ipEntry)
				sh.mu.Unlock()
			}
			rl.size.Store(0)
			return
		case <-ticker.C:
			now := time.Now().UnixNano()
			cutoff := now - rl.ttl
			var removed int64
			for i := range rl.shards {
				sh := &rl.shards[i]
				sh.mu.Lock()
				for k, e := range sh.m {
					if e.lastSeen.Load() < cutoff {
						delete(sh.m, k)
						removed++
					}
				}
				sh.mu.Unlock()
			}
			if removed > 0 {
				rl.size.Add(-removed)
			}
		}
	}
}
