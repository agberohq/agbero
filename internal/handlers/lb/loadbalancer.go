package lb

import (
	"context"
	"math"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/handlers/backend"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/clientip"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
)

type snapshotHolder struct {
	backends []*backend.Backend
	wheel    *weightWheel

	hasConditions bool
	weightsAllOne bool
}

type LoadBalancer struct {
	strategy    uint8
	timeout     time.Duration
	stripPrefix []string

	state     atomic.Value
	rrCounter atomic.Uint64
}

func NewLoadBalancer(backends []*backend.Backend, strategy string, timeout time.Duration, stripPrefixes []string) *LoadBalancer {
	lb := &LoadBalancer{
		timeout:     timeout,
		stripPrefix: append([]string(nil), stripPrefixes...),
	}
	lb.setStrategy(strategy)
	lb.Update(backends)
	return lb
}

func (lb *LoadBalancer) Update(list []*backend.Backend) {
	cp := make([]*backend.Backend, 0, len(list))
	hasCond := false

	for _, b := range list {
		if b == nil {
			continue
		}
		cp = append(cp, b)
		if !hasCond && b.Cond != nil && b.Cond.HasRules() {
			hasCond = true
		}
	}

	wheel := buildWheel(cp)
	weightsAllOne := wheel == nil || len(wheel.cumul) == 0

	lb.state.Store(&snapshotHolder{
		backends:      cp,
		wheel:         wheel,
		hasConditions: hasCond,
		weightsAllOne: weightsAllOne,
	})
}

func (lb *LoadBalancer) Snapshot() []*backend.Backend {
	holder := lb.getHolder()
	if holder == nil || len(holder.backends) == 0 {
		return nil
	}
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

	if holder.hasConditions {
		if be, handled := lb.pickByConditions(list, wheel, r, holder.weightsAllOne); handled {
			return be
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
	case woos.StIPHash:
		return lb.pickIPHash(list, w, r)
	case woos.StURLHash:
		return lb.pickURLHash(list, w, r)
	case woos.StLeastConn:
		return lb.pickLeastConn(list)
	case woos.StRandom:
		return lb.pickRandom(list, w)
	case woos.StWeightedLeastConn:
		return lb.pickWeightedLeastConn(list)
	default:
		return lb.pickRoundRobin(list, w)
	}
}

func (lb *LoadBalancer) pickRoundRobin(list []*backend.Backend, w *weightWheel) *backend.Backend {
	if w != nil && w.total > 0 && len(w.cumul) > 0 {
		for i := 0; i < len(list); i++ {
			idx := w.next(lb.rrCounter.Add(1))
			if idx >= 0 && idx < len(list) && list[idx].Alive.Load() {
				return list[idx]
			}
		}
		return nil
	}

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
	r := rngPool.Get().(*rand.Rand)
	defer rngPool.Put(r)

	if w == nil || w.total == 0 || len(w.cumul) == 0 {
		start := r.IntN(len(list))
		for i := 0; i < len(list); i++ {
			idx := (start + i) % len(list)
			if list[idx].Alive.Load() {
				return list[idx]
			}
		}
		return nil
	}

	target := r.Uint64N(w.total)
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
		key = woos.Slash
	}
	return lb.hashPick(list, w, key)
}

func (lb *LoadBalancer) hashPick(list []*backend.Backend, w *weightWheel, key string) *backend.Backend {
	h := lb.hashStr(key)

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
		if c := b.Activity.InFlight.Load(); c < min {
			min = c
			best = b
		}
	}
	return best
}

func (lb *LoadBalancer) pickWeightedLeastConn(list []*backend.Backend) *backend.Backend {
	var best *backend.Backend
	bestRatio := -1.0

	for _, b := range list {
		if b == nil || !b.Alive.Load() {
			continue
		}

		w := float64(b.Weight)
		if w <= 0 {
			w = 1
		}
		c := float64(b.Activity.InFlight.Load() + 1)
		ratio := c / w

		if best == nil || ratio < bestRatio {
			best = b
			bestRatio = ratio
		}
	}
	return best
}

func (lb *LoadBalancer) pickByConditions(
	list []*backend.Backend,
	snapshotWheel *weightWheel,
	r *http.Request,
	weightsAllOne bool,
) (*backend.Backend, bool) {

	var matchedHealthy []*backend.Backend
	anyMatch := false

	for _, b := range list {
		if b == nil || b.Cond == nil || !b.Cond.HasRules() {
			continue
		}
		if !b.Cond.Match(r) {
			continue
		}
		anyMatch = true
		if b.Alive.Load() {
			matchedHealthy = append(matchedHealthy, b)
		}
	}

	if !anyMatch || len(matchedHealthy) == 0 {
		return nil, false
	}

	if weightsAllOne {
		return lb.pickWithList(matchedHealthy, nil, r), true
	}

	return lb.pickWithList(matchedHealthy, buildWheel(matchedHealthy), r), true
}

func (lb *LoadBalancer) setStrategy(s string) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case strings.ToLower(alaye.StrategyIPHash):
		lb.strategy = woos.StIPHash
	case strings.ToLower(alaye.StrategyURLHash):
		lb.strategy = woos.StURLHash
	case strings.ToLower(alaye.StrategyLeastConn):
		lb.strategy = woos.StLeastConn
	case strings.ToLower(alaye.StrategyRandom):
		lb.strategy = woos.StRandom
	case strings.ToLower(alaye.StrategyWeightedLeastConn):
		lb.strategy = woos.StWeightedLeastConn
	default:
		lb.strategy = woos.StRoundRobin
	}
}

func (lb *LoadBalancer) hashStr(s string) uint64 {
	var h uint64 = 5381
	for i := 0; i < len(s); i++ {
		h = ((h << 5) + h) + uint64(s[i])
	}
	return h
}
