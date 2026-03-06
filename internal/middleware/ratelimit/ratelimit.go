package ratelimit

import (
	"net/http"
	"path"
	"strings"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/zulu"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/lb"
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

type Config struct {
	TTL             time.Duration
	MaxEntries      int
	Policy          func(r *http.Request) (bucket string, pol RatePolicy, ok bool)
	IPManager       *zulu.IPManager
	CleanupInterval time.Duration
}

var packedBits = []uint8{32, 32}

type atomicEntry struct {
	state zulu.AtomicPacked
	lim   *rate.Limiter
}

type RateLimiter struct {
	data       *mappo.Sharded[string, *atomicEntry]
	policy     func(r *http.Request) (bucket string, pol RatePolicy, ok bool)
	ttl        int64
	maxEntries int
	scheduler  *jack.Scheduler
	ipMgr      *zulu.IPManager
}

func New(cfg Config) *RateLimiter {
	if cfg.TTL <= 0 {
		cfg.TTL = 30 * time.Minute
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 100_000
	}
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = 5 * time.Minute
	}

	rl := &RateLimiter{
		data:       mappo.NewSharded[string, *atomicEntry](),
		policy:     cfg.Policy,
		ttl:        cfg.TTL.Nanoseconds(),
		maxEntries: cfg.MaxEntries,
		ipMgr:      cfg.IPManager,
	}

	sched, _ := jack.NewScheduler("ratelimit-gc", jack.NewPool(1), jack.Routine{
		Interval: cfg.CleanupInterval,
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

func (rl *RateLimiter) allowInternal(key string, pol RatePolicy) bool {
	if pol.Requests <= 0 {
		return true
	}
	now := time.Now().Unix()
	allowed := true
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
	if keySpec == "" || strings.EqualFold(keySpec, "ip") {
		if rl.ipMgr != nil {
			return rl.ipMgr.ClientIP(r)
		}
		return r.RemoteAddr
	}

	extract := lb.Extractor([]string{keySpec})
	val := extract(r)
	if val != "" {
		return val
	}

	if rl.ipMgr != nil {
		return rl.ipMgr.ClientIP(r)
	}
	return r.RemoteAddr
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
