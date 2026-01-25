package lb

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"math"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/handlers/backend"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/clientip"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
)

const (
	stRoundRobin uint8 = iota
	stIPHash
	stURLHash
	stLeastConn
	stRandom
	stWeightedLeastConn
)

// We only use crypto/rand once per pooled RNG instance (seed).
var rngPool = sync.Pool{
	New: func() any {
		var seed uint64
		_ = binary.Read(rand.Reader, binary.LittleEndian, &seed)
		return newRng(seed)
	},
}

type LoadBalancer struct {
	// immutable after build / config
	strategy    uint8
	timeout     time.Duration
	stripPrefix []string

	// hot path: read-only after UpdateBackends()
	backends atomic.Value // -> *[]*backend.Backend

	rrCounter atomic.Uint64
}

func NewLoadBalancer(backends []*backend.Backend, strategy string, timeout time.Duration, stripPrefixes []string) *LoadBalancer {
	lb := &LoadBalancer{
		timeout:     timeout,
		stripPrefix: append([]string(nil), stripPrefixes...),
	}
	lb.setStrategy(strategy)
	lb.UpdateBackends(backends)
	return lb
}

func (lb *LoadBalancer) UpdateBackends(list []*backend.Backend) {
	cp := make([]*backend.Backend, 0, len(list))
	for _, b := range list {
		if b == nil {
			continue
		}
		cp = append(cp, b)
	}
	lb.backends.Store(&cp)
}

func (lb *LoadBalancer) Snapshot() []*backend.Backend {
	s := lb.mustSnapshot()
	if len(s) == 0 {
		return nil
	}
	out := make([]*backend.Backend, len(s))
	copy(out, s)
	return out
}

func (lb *LoadBalancer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	be := lb.PickBackend(r)
	if be == nil {
		http.Error(w, "no healthy backends", http.StatusBadGateway)
		return
	}

	ctx := r.Context()
	if lb.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, lb.timeout)
		defer cancel()
	}

	be.ServeHTTP(w, r.WithContext(ctx))
}

func (lb *LoadBalancer) PickBackend(r *http.Request) *backend.Backend {
	list := lb.mustSnapshot()
	if len(list) == 0 {
		return nil
	}

	// Conditions can narrow the candidate pool.
	// IMPORTANT: must not break selection indices (wheel must be built on the candidate slice).
	list = lb.filterByConditions(list, r)
	if len(list) == 0 {
		return nil
	}

	if len(list) == 1 {
		if list[0].Alive.Load() {
			return list[0]
		}
		return nil
	}

	switch lb.strategy {
	case stIPHash:
		return lb.pickIPHash(list, r)
	case stURLHash:
		return lb.pickURLHash(list, r)
	case stLeastConn:
		return lb.pickLeastConn(list)
	case stRandom:
		return lb.pickRandom(list)
	case stWeightedLeastConn:
		return lb.pickWeightedLeastConn(list)
	default:
		return lb.pickRoundRobin(list)
	}
}

/* ---------- strategy parsing ------------------------------------------------ */

func (lb *LoadBalancer) setStrategy(s string) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case strings.ToLower(alaye.StrategyIPHash):
		lb.strategy = stIPHash
	case strings.ToLower(alaye.StrategyURLHash):
		lb.strategy = stURLHash
	case strings.ToLower(alaye.StrategyLeastConn):
		lb.strategy = stLeastConn
	case strings.ToLower(alaye.StrategyRandom):
		lb.strategy = stRandom
	case strings.ToLower(alaye.StrategyWeightedLeastConn):
		lb.strategy = stWeightedLeastConn
	default:
		lb.strategy = stRoundRobin
	}
}

/* ---------- snapshot helpers ------------------------------------------------ */

func (lb *LoadBalancer) mustSnapshot() []*backend.Backend {
	if v := lb.backends.Load(); v != nil {
		return *(v.(*[]*backend.Backend))
	}
	return nil
}

/* ---------- pick strategies (SAFE after filtering) -------------------------- */

func (lb *LoadBalancer) pickRoundRobin(list []*backend.Backend) *backend.Backend {
	// ✅ build wheel on candidate slice (avoids OOR after filterByConditions)
	w := buildWheel(list)

	// Weighted wheel RR.
	if w != nil && w.total > 0 {
		for i := 0; i < len(list); i++ {
			idx := w.next(lb.rrCounter.Add(1))
			if idx >= 0 && idx < len(list) && list[idx].Alive.Load() {
				return list[idx]
			}
		}
		return nil
	}

	// Fallback: plain RR.
	start := lb.rrCounter.Add(1)
	n := uint64(len(list))
	for i := 0; i < len(list); i++ {
		idx := int((start + uint64(i)) % n)
		if list[idx].Alive.Load() {
			return list[idx]
		}
	}
	return nil
}

func (lb *LoadBalancer) pickRandom(list []*backend.Backend) *backend.Backend {
	// ✅ build wheel on candidate slice (avoids OOR after filterByConditions)
	w := buildWheel(list)

	// Treat as uniform if weights are all 1 (wheel total == len(list)).
	if w == nil || w.total == 0 || w.total == uint64(len(list)) {
		r := rngPool.Get().(*rng)
		start := r.Uint64n(uint64(len(list)))
		rngPool.Put(r)

		n := uint64(len(list))
		for i := 0; i < len(list); i++ {
			idx := int((start + uint64(i)) % n)
			if list[idx].Alive.Load() {
				return list[idx]
			}
		}
		return nil
	}

	// Weighted: pick by cumulative weights, then bounded scan if chosen is dead.
	r := rngPool.Get().(*rng)
	target := r.Uint64n(w.total)
	rngPool.Put(r)

	idx := w.search(target)
	if idx >= 0 && idx < len(list) && list[idx].Alive.Load() {
		return list[idx]
	}
	for i := 1; i < len(list); i++ {
		j := (idx + i) % len(list)
		if list[j].Alive.Load() {
			return list[j]
		}
	}
	return nil
}

func (lb *LoadBalancer) pickIPHash(list []*backend.Backend, r *http.Request) *backend.Backend {
	key := clientip.ClientIP(r)
	if key == "" {
		return lb.pickRoundRobin(list)
	}
	return lb.hashPick(list, key)
}

func (lb *LoadBalancer) pickURLHash(list []*backend.Backend, r *http.Request) *backend.Backend {
	key := r.URL.Path
	if key == "" {
		key = "/"
	}
	return lb.hashPick(list, key)
}

func (lb *LoadBalancer) hashPick(list []*backend.Backend, key string) *backend.Backend {
	h := hashStr(key)

	// ✅ build wheel on candidate slice (avoids OOR after filterByConditions)
	w := buildWheel(list)

	if w == nil || w.total == 0 || w.total == uint64(len(list)) {
		// uniform
		idx := int(h % uint64(len(list)))
		if list[idx].Alive.Load() {
			return list[idx]
		}
		return lb.pickRandom(list)
	}

	// weighted
	idx := w.search(h % w.total)
	if idx >= 0 && idx < len(list) && list[idx].Alive.Load() {
		return list[idx]
	}
	return lb.pickRandom(list)
}

func (lb *LoadBalancer) pickLeastConn(list []*backend.Backend) *backend.Backend {
	var best *backend.Backend
	min := int64(math.MaxInt64)

	for _, b := range list {
		if b == nil || !b.Alive.Load() {
			continue
		}
		if c := b.InFlight.Load(); c < min {
			min = c
			best = b
		}
	}
	return best
}

func (lb *LoadBalancer) pickWeightedLeastConn(list []*backend.Backend) *backend.Backend {
	var best *backend.Backend
	var bestW uint64
	var bestC uint64

	for _, b := range list {
		if b == nil || !b.Alive.Load() {
			continue
		}

		w := uint64(b.Weight)
		if w == 0 {
			w = 1
		}
		c := uint64(b.InFlight.Load() + 1)

		if best == nil {
			best, bestW, bestC = b, w, c
			continue
		}

		// Compare w/c > bestW/bestC using cross-multiplication:
		// w*bestC > bestW*c
		if w*bestC > bestW*c {
			best, bestW, bestC = b, w, c
		}
	}

	return best
}

/* ---------- conditions ------------------------------------------------------ */

// NOTE: this expects your backend.Backend to expose:
//   - b.Cond != nil
//   - b.Cond.HasRules() bool
//   - b.Cond.Match(*http.Request) bool
//
// Production-safe behavior:
//   - If any backends match rules AND at least one matched backend is healthy => use matched set
//   - If matches exist but all matched are DOWN => fall back to full pool (avoid accidental 502s)
//   - If no matches => use full pool
func (lb *LoadBalancer) filterByConditions(list []*backend.Backend, r *http.Request) []*backend.Backend {
	if len(list) == 0 {
		return nil
	}

	var matched []*backend.Backend
	var matchedHealthy []*backend.Backend

	for _, b := range list {
		if b == nil || b.Cond == nil || !b.Cond.HasRules() {
			continue
		}
		if b.Cond.Match(r) {
			matched = append(matched, b)
			if b.Alive.Load() {
				matchedHealthy = append(matchedHealthy, b)
			}
		}
	}

	// No rules matched => default pool.
	if len(matched) == 0 {
		return list
	}

	// Rules matched and some are healthy => restrict to matched (healthy or not is handled by pickers).
	// We prefer the healthy-only slice to reduce scans.
	if len(matchedHealthy) > 0 {
		return matchedHealthy
	}

	// Rules matched but all targets are down => fall back to default pool.
	return list
}

/* ---------- wheel helpers --------------------------------------------------- */

type weightWheel struct {
	cumul []uint64 // strictly increasing cumulative weights
	total uint64
}

func buildWheel(list []*backend.Backend) *weightWheel {
	if len(list) == 0 {
		return &weightWheel{}
	}

	cumul := make([]uint64, len(list))
	var sum uint64

	for i, b := range list {
		w := uint64(1)
		if b != nil && b.Weight > 0 {
			w = uint64(b.Weight)
		}
		sum += w
		cumul[i] = sum
	}

	return &weightWheel{cumul: cumul, total: sum}
}

func (w *weightWheel) next(counter uint64) int {
	if w == nil || w.total == 0 {
		return 0
	}
	target := counter % w.total
	return w.search(target)
}

func (w *weightWheel) search(target uint64) int {
	// lower_bound: first index with cumul[i] > target
	i, j := 0, len(w.cumul)
	for i < j {
		h := int(uint(i+j) >> 1)
		if w.cumul[h] <= target {
			i = h + 1
		} else {
			j = h
		}
	}
	if i >= len(w.cumul) {
		return len(w.cumul) - 1
	}
	return i
}

/* ---------- misc ------------------------------------------------------------ */

// cheap hash (djb2)
func hashStr(s string) uint64 {
	var h uint64 = 5381
	for i := 0; i < len(s); i++ {
		h = ((h << 5) + h) + uint64(s[i])
	}
	return h
}

// fast rng (xoshiro256+ style)
type rng struct {
	s [4]uint64
}

func newRng(seed uint64) *rng {
	var r rng
	// Simple expansion; good enough for load balancing randomness.
	r.s[0] = seed
	r.s[1] = seed*0x9e3779b97f4a7c15 + 0xbf58476d1ce4e5b9
	r.s[2] = seed ^ 0x94d049bb133111eb
	r.s[3] = seed + 0x2545f4914f6cdd1d
	return &r
}

func (r *rng) Uint64() uint64 {
	x := r.s[0]
	y := r.s[3]
	result := x + y

	y ^= x
	r.s[0] = rotl(x, 24) ^ y ^ (y << 16)
	r.s[3] = rotl(y, 37)
	return result
}

func (r *rng) Uint64n(n uint64) uint64 {
	if n == 0 {
		return 0
	}
	mask := n - 1
	if (n & mask) == 0 {
		return r.Uint64() & mask
	}
	limit := math.MaxUint64 - (math.MaxUint64 % n)
	for {
		v := r.Uint64()
		if v < limit {
			return v % n
		}
	}
}

func rotl(x uint64, k int) uint64 { return (x << k) | (x >> (64 - k)) }
