package ratelimit

import (
	"net/http"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/middleware/clientip"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/mappo"
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
	lastSeen atomic.Int64
}

type RateLimiter struct {
	data       *mappo.Sharded[string, *ipEntry]
	policy     func(r *http.Request) (bucket string, pol RatePolicy, ok bool)
	ttl        int64 // nanoseconds
	maxEntries int
	scheduler  *jack.Scheduler
}

func NewRateLimiter(ttl time.Duration, maxEntries int64, policy func(r *http.Request) (bucket string, pol RatePolicy, ok bool)) *RateLimiter {
	rl := &RateLimiter{
		data:       mappo.NewShardedWithConfig[string, *ipEntry](mappo.ShardedConfig{ShardCount: 256}),
		policy:     policy,
		ttl:        ttl.Nanoseconds(),
		maxEntries: int(maxEntries),
	}

	if rl.ttl <= 0 {
		rl.ttl = 30 * time.Minute.Nanoseconds()
	}
	if rl.maxEntries <= 0 {
		rl.maxEntries = 100_000
	}

	// Start Janitor using jack.Scheduler
	sched, _ := jack.NewScheduler("ratelimit-gc", jack.NewPool(1), jack.Routine{
		Interval: 5 * time.Minute,
	})
	_ = sched.Do(jack.Do(rl.sweeper))
	rl.scheduler = sched

	return rl
}

func (rl *RateLimiter) Close() {
	if rl.scheduler != nil {
		_ = rl.scheduler.Stop()
	}
	rl.data.Clear()
}

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

		bucketName, pol, ok := rl.policy(r)
		if !ok || pol.Requests <= 0 {
			next.ServeHTTP(w, r)
			return
		}

		key := rl.extractKey(r, pol.KeySpec)
		fullKey := bucketName + ":" + key

		now := time.Now().UnixNano()

		// Atomic Get-Or-Create-Or-Update
		entry := rl.data.Compute(fullKey, func(curr *ipEntry, exists bool) (*ipEntry, bool) {
			if exists {
				// Update existing timestamp
				curr.lastSeen.Store(now)
				return curr, true
			}
			// Enforce size limit
			// Note: rl.data.Len() is an estimate, but safer than iterating shards inside a lock
			if rl.data.Len() >= rl.maxEntries {
				return nil, false
			}
			return &ipEntry{
				lim:      pol.limiter(),
				lastSeen: atomic.Int64{}, // Will set below, or initialize here
			}, true
		})

		if entry == nil {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		if entry.lastSeen.Load() == 0 {
			entry.lastSeen.Store(now)
		}

		if !entry.lim.Allow() {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) extractKey(r *http.Request, keySpec string) string {
	if keySpec == "" {
		return clientip.ClientIP(r)
	}
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
	now := time.Now().UnixNano()
	cutoff := now - rl.ttl

	rl.data.ClearIf(func(key string, e *ipEntry) bool {
		return e.lastSeen.Load() < cutoff
	})
}
