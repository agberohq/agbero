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

var rngPool = sync.Pool{
	New: func() any {
		var seed uint64
		_ = binary.Read(rand.Reader, binary.LittleEndian, &seed)
		return newRng(seed)
	},
}

// snapshotHolder stores immutable state for the current config generation
type snapshotHolder struct {
	backends []*backend.Backend
	wheel    *weightWheel
}

type LoadBalancer struct {
	strategy    uint8
	timeout     time.Duration
	stripPrefix []string

	state     atomic.Value // holds *snapshotHolder
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
	// Filter nils and create clean copy
	cp := make([]*backend.Backend, 0, len(list))
	for _, b := range list {
		if b != nil {
			cp = append(cp, b)
		}
	}

	// Pre-calculate selection wheel
	wheel := buildWheel(cp)

	lb.state.Store(&snapshotHolder{
		backends: cp,
		wheel:    wheel,
	})
}

// Snapshot returns a copy of the current backend list (Requested by Metrics)
func (lb *LoadBalancer) Snapshot() []*backend.Backend {
	holder := lb.getHolder()
	if holder == nil || len(holder.backends) == 0 {
		return nil
	}
	// Return slice directly as it is treated as immutable once stored
	return holder.backends
}

func (lb *LoadBalancer) getHolder() *snapshotHolder {
	val := lb.state.Load()
	if val == nil {
		return nil
	}
	return val.(*snapshotHolder)
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
	holder := lb.getHolder()
	if holder == nil || len(holder.backends) == 0 {
		return nil
	}

	list := holder.backends
	wheel := holder.wheel

	// Check for conditions (e.g. source IP restrictions)
	// Optimization: Only scan for conditions if at least one backend has them
	hasConditions := false
	for _, b := range list {
		if b.Cond != nil && b.Cond.HasRules() {
			hasConditions = true
			break
		}
	}

	if hasConditions {
		filtered := lb.filterByConditions(list, r)
		if len(filtered) == 0 {
			return nil
		}
		// If filtering occurred, we must rebuild a temporary wheel or use simple selection
		if len(filtered) != len(list) {
			return lb.pickWithList(filtered, buildWheel(filtered), r)
		}
	}

	return lb.pickWithList(list, wheel, r)
}

func (lb *LoadBalancer) pickWithList(list []*backend.Backend, w *weightWheel, r *http.Request) *backend.Backend {
	if len(list) == 1 {
		if list[0].Alive.Load() {
			return list[0]
		}
		return nil
	}

	switch lb.strategy {
	case stIPHash:
		return lb.pickIPHash(list, w, r)
	case stURLHash:
		return lb.pickURLHash(list, w, r)
	case stLeastConn:
		return lb.pickLeastConn(list)
	case stRandom:
		return lb.pickRandom(list, w)
	case stWeightedLeastConn:
		return lb.pickWeightedLeastConn(list)
	default:
		return lb.pickRoundRobin(list, w)
	}
}

func (lb *LoadBalancer) pickRoundRobin(list []*backend.Backend, w *weightWheel) *backend.Backend {
	// Weighted Round Robin
	if w != nil && w.total > 0 && len(w.cumul) > 0 {
		for i := 0; i < len(list); i++ {
			idx := w.next(lb.rrCounter.Add(1))
			if idx >= 0 && idx < len(list) && list[idx].Alive.Load() {
				return list[idx]
			}
		}
		return nil
	}

	// Simple Round Robin (Uniform)
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

func (lb *LoadBalancer) pickRandom(list []*backend.Backend, w *weightWheel) *backend.Backend {
	// Uniform Random
	if w == nil || w.total == 0 || len(w.cumul) == 0 {
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

	// Weighted Random
	r := rngPool.Get().(*rng)
	target := r.Uint64n(w.total)
	rngPool.Put(r)

	idx := w.search(target)
	if idx >= 0 && idx < len(list) && list[idx].Alive.Load() {
		return list[idx]
	}

	// Fallback linear scan if weighted pick is dead
	for i := 1; i < len(list); i++ {
		j := (idx + i) % len(list)
		if list[j].Alive.Load() {
			return list[j]
		}
	}
	return nil
}

func (lb *LoadBalancer) pickIPHash(list []*backend.Backend, w *weightWheel, r *http.Request) *backend.Backend {
	key := clientip.ClientIP(r)
	if key == "" {
		return lb.pickRoundRobin(list, w)
	}
	return lb.hashPick(list, w, key)
}

func (lb *LoadBalancer) pickURLHash(list []*backend.Backend, w *weightWheel, r *http.Request) *backend.Backend {
	key := r.URL.Path
	if key == "" {
		key = "/"
	}
	return lb.hashPick(list, w, key)
}

func (lb *LoadBalancer) hashPick(list []*backend.Backend, w *weightWheel, key string) *backend.Backend {
	h := hashStr(key)

	if w == nil || w.total == 0 || len(w.cumul) == 0 {
		idx := int(h % uint64(len(list)))
		if list[idx].Alive.Load() {
			return list[idx]
		}
		return lb.pickRandom(list, w)
	}

	idx := w.search(h % w.total)
	if idx >= 0 && idx < len(list) && list[idx].Alive.Load() {
		return list[idx]
	}
	return lb.pickRandom(list, w)
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
	var bestRatio float64 = -1

	for _, b := range list {
		if b == nil || !b.Alive.Load() {
			continue
		}

		w := float64(b.Weight)
		if w <= 0 {
			w = 1
		}

		// Active connections + 1 to avoid division by zero
		c := float64(b.InFlight.Load() + 1)

		// We want to minimize Connections / Weight
		ratio := c / w

		if best == nil || ratio < bestRatio {
			best = b
			bestRatio = ratio
		}
	}
	return best
}

func (lb *LoadBalancer) filterByConditions(list []*backend.Backend, r *http.Request) []*backend.Backend {
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

	if len(matched) == 0 {
		return list
	}
	if len(matchedHealthy) > 0 {
		return matchedHealthy
	}
	return list
}

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

// Weight Wheel Logic
type weightWheel struct {
	cumul []uint64
	total uint64
}

func buildWheel(list []*backend.Backend) *weightWheel {
	if len(list) == 0 {
		return &weightWheel{}
	}
	cumul := make([]uint64, len(list))
	var sum uint64
	allOne := true

	for i, b := range list {
		w := uint64(1)
		if b != nil && b.Weight > 0 {
			w = uint64(b.Weight)
		}
		if w != 1 {
			allOne = false
		}
		sum += w
		cumul[i] = sum
	}

	// Optimization: If all weights are 1, return empty cumul to signal uniform distribution
	if allOne {
		return &weightWheel{total: sum, cumul: nil}
	}
	return &weightWheel{cumul: cumul, total: sum}
}

func (w *weightWheel) next(counter uint64) int {
	if w == nil || w.total == 0 {
		return 0
	}
	if len(w.cumul) == 0 {
		return int(counter % w.total)
	}
	target := counter % w.total
	return w.search(target)
}

func (w *weightWheel) search(target uint64) int {
	if len(w.cumul) == 0 {
		return int(target)
	}

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

func hashStr(s string) uint64 {
	var h uint64 = 5381
	for i := 0; i < len(s); i++ {
		h = ((h << 5) + h) + uint64(s[i])
	}
	return h
}

type rng struct {
	s [4]uint64
}

func newRng(seed uint64) *rng {
	var r rng
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
