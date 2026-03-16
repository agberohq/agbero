package ratelimit

import (
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/cluster"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/pkg/wellknown"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/mappo"
	"golang.org/x/time/rate"
)

const (
	defaultCleanupInterval = 5 * time.Minute
	emptyRequestsAllowed   = 0
	gcRoutineName          = "ratelimit-gc"
	gcRoutinePoolSize      = 1
)

var packedBits = []uint8{16, 48}

type RatePolicy struct {
	Requests int
	Window   time.Duration
	Burst    int
	KeySpec  string
}

// limiter constructs a standard rate limiter from the defined policy
// Reverts to an infinite limiter if the request quota is missing or invalid
func (p RatePolicy) limiter() *rate.Limiter {
	if p.Requests <= emptyRequestsAllowed {
		return rate.NewLimiter(rate.Inf, emptyRequestsAllowed)
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

type Config struct {
	TTL             time.Duration
	MaxEntries      int
	Policy          func(r *http.Request) (bucket string, pol RatePolicy, ok bool)
	IPManager       *zulu.IPManager
	CleanupInterval time.Duration
	SharedState     cluster.SharedState
}

type atomicEntry struct {
	state zulu.AtomicPacked
	lim   *rate.Limiter
}

type RateLimiter struct {
	data        *mappo.Sharded[string, *atomicEntry]
	policy      func(r *http.Request) (bucket string, pol RatePolicy, ok bool)
	ttl         int64
	maxEntries  int
	scheduler   *jack.Scheduler
	ipMgr       *zulu.IPManager
	sharedState cluster.SharedState
}

// New instantiates a dynamic request throttling layer
// Handles both local token buckets and shared cluster constraints automatically
func New(cfg Config) *RateLimiter {
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = defaultCleanupInterval
	}

	rl := &RateLimiter{
		data:        mappo.NewSharded[string, *atomicEntry](),
		policy:      cfg.Policy,
		ttl:         cfg.TTL.Nanoseconds(),
		maxEntries:  cfg.MaxEntries,
		ipMgr:       cfg.IPManager,
		sharedState: cfg.SharedState,
	}

	sched, _ := jack.NewScheduler(gcRoutineName, jack.NewPool(gcRoutinePoolSize), jack.Routine{
		Interval: cfg.CleanupInterval,
	})

	_ = sched.Do(jack.Do(rl.sweeper))
	rl.scheduler = sched

	return rl
}

// Close terminates the background cleanup scheduler and flushes map data
// Prevents memory leaks during proxy hot-reloads and shutdowns
func (rl *RateLimiter) Close() {
	if rl.scheduler != nil {
		_ = rl.scheduler.Stop()
	}
	rl.data.Clear()
}

// allowInternal evaluates the request against the shared or local token bucket
// Utilizes 48-bit packed timestamps to avoid Y2K38 overflow panics
func (rl *RateLimiter) allowInternal(r *http.Request, key string, pol RatePolicy) bool {
	if pol.Requests <= emptyRequestsAllowed {
		return true
	}

	if rl.sharedState != nil {
		allowed, err := rl.sharedState.AllowRateLimit(r.Context(), key, pol.Requests, pol.Window, pol.Burst)
		if err != nil {
			return true
		}
		return allowed
	}

	now := time.Now().Unix()

	if curr, ok := rl.data.Get(key); ok {
		for {
			oldPacked := curr.state.Load()
			newPacked := zulu.NewPacked(packedBits, 0, now)
			if curr.state.CompareAndSwap(oldPacked, newPacked) {
				break
			}
		}
		return curr.lim.Allow()
	}

	var allowed bool
	rl.data.Compute(key, func(curr *atomicEntry, exists bool) (*atomicEntry, bool) {
		if exists {
			for {
				oldPacked := curr.state.Load()
				newPacked := zulu.NewPacked(packedBits, 0, now)
				if curr.state.CompareAndSwap(oldPacked, newPacked) {
					break
				}
			}
			allowed = curr.lim.Allow()
			return curr, true
		}
		if rl.data.Len() >= rl.maxEntries {
			allowed = false
			return nil, false
		}
		newEntry := &atomicEntry{
			lim: pol.limiter(),
		}
		newEntry.state.Store(zulu.NewPacked(packedBits, 0, now))
		allowed = newEntry.lim.Allow()
		return newEntry, true
	})
	return allowed
}

// Handler enforces endpoint request ceilings across incoming connections
// Responds with 429 Too Many Requests instantly upon limit saturation
func (rl *RateLimiter) Handler(next http.Handler) http.Handler {
	if rl == nil || rl.policy == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cleanPath := path.Clean(r.URL.Path)
		if wellknown.IsACMEChallengePrefix(cleanPath) {
			next.ServeHTTP(w, r)
			return
		}
		bucketName, pol, ok := rl.policy(r)
		if !ok || pol.Requests <= emptyRequestsAllowed {
			next.ServeHTTP(w, r)
			return
		}
		key := rl.extractKey(r, pol.KeySpec)
		fullKey := bucketName + ":" + key
		if !rl.allowInternal(r, fullKey, pol) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// extractKey identifies the unique client signature for the bucket
// Defaults to the IP address if the specified extractor yields no data
func (rl *RateLimiter) extractKey(r *http.Request, keySpec string) string {
	if keySpec == "" || strings.EqualFold(keySpec, "ip") {
		if rl.ipMgr != nil {
			return rl.ipMgr.ClientIP(r)
		}
		return r.RemoteAddr
	}

	extract := zulu.Extractor([]string{keySpec})
	val := extract(r)
	if val != "" {
		return val
	}

	if rl.ipMgr != nil {
		return rl.ipMgr.ClientIP(r)
	}
	return r.RemoteAddr
}

// sweeper removes stale rate limit entries from the memory cache
// Runs periodically via the scheduler to maintain bounded map sizes
func (rl *RateLimiter) sweeper() {
	now := time.Now().Unix()
	cutoff := now - (rl.ttl / time.Second.Nanoseconds())
	rl.data.ClearIf(func(key string, e *atomicEntry) bool {
		values := e.state.Load().Extract(packedBits)
		lastSeen := values[1]
		return lastSeen < cutoff
	})
}
