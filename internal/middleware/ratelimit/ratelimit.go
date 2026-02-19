package ratelimit

import (
	"net/http"
	"path"
	"strings"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/zulu"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/clientip"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/mappo"
	"golang.org/x/time/rate"
)

type RatePolicy struct {
	Requests int
	Window   time.Duration
	Burst    int
	KeySpec  string
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

// Bit layout: [32 bits reserved | 32 bits lastSeen timestamp]
var packedBits = []uint8{32, 32}

// atomicEntry holds the rate limiter and atomic packed state
type atomicEntry struct {
	state zulu.AtomicPacked
	lim   *rate.Limiter // Immutable after creation
}

// RateLimiter maintains backward compatible API
type RateLimiter struct {
	data       *mappo.Sharded[string, *atomicEntry]
	policy     func(r *http.Request) (bucket string, pol RatePolicy, ok bool)
	ttl        int64
	maxEntries int
	scheduler  *jack.Scheduler
}

// NewRateLimiter creates a new rate limiter (backward compatible)
func NewRateLimiter(ttl time.Duration, maxEntries int64, policy func(r *http.Request) (bucket string, pol RatePolicy, ok bool)) *RateLimiter {
	rl := &RateLimiter{
		data:       mappo.NewSharded[string, *atomicEntry](),
		policy:     policy,
		ttl:        ttl.Nanoseconds(),
		maxEntries: int(maxEntries),
	}

	if rl.ttl <= 0 {
		rl.ttl = int64(30 * time.Minute)
	}
	if rl.maxEntries <= 0 {
		rl.maxEntries = 100_000
	}

	// Start Janitor
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

// allowInternal checks rate limit using atomic operations
func (rl *RateLimiter) allowInternal(key string, pol RatePolicy) bool {
	if pol.Requests <= 0 {
		return true
	}

	now := time.Now().Unix()
	allowed := true

	// Use Compute for atomic get-or-create
	rl.data.Compute(key, func(curr *atomicEntry, exists bool) (*atomicEntry, bool) {
		if exists {
			// Update last seen atomically using CAS loop
			for {
				oldPacked := curr.state.Load()
				// Extract: values[0]=reserved, values[1]=lastSeen
				newPacked := zulu.NewPacked(packedBits, 0, now)
				if curr.state.CompareAndSwap(oldPacked, newPacked) {
					break
				}
			}
			// Check rate limit
			allowed = curr.lim.Allow()
			return curr, true // Keep entry
		}

		// Enforce max entries
		if rl.data.Len() >= rl.maxEntries {
			allowed = false
			return nil, false // Don't create
		}

		// Create new entry
		newEntry := &atomicEntry{
			lim: pol.limiter(),
		}
		newEntry.state.Store(zulu.NewPacked(packedBits, 0, now))
		allowed = newEntry.lim.Allow()
		return newEntry, true
	})

	return allowed
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

		if !rl.allowInternal(fullKey, pol) {
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
	now := time.Now().Unix()
	cutoff := now - (rl.ttl / 1e9)

	rl.data.ClearIf(func(key string, e *atomicEntry) bool {
		values := e.state.Load().Extract(packedBits)
		lastSeen := values[1]
		return lastSeen < cutoff
	})
}
