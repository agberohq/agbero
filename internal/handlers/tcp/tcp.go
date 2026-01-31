package tcp

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"strings"
	"sync/atomic"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
)

type TCPBackend struct {
	Address     string
	Weight      int
	ActiveConns atomic.Int64
}
type TCPBalancer struct {
	backends  []*TCPBackend
	strategy  int
	rrCounter atomic.Uint64
}

func newTCPBalancer(cfg alaye.TCPRoute) *TCPBalancer {
	var backends []*TCPBackend
	for _, b := range cfg.Backends {
		w := b.Weight
		if w <= 0 {
			w = 1
		}
		backends = append(backends, &TCPBackend{
			Address: b.Address,
			Weight:  w,
		})
	}

	strat := woos.StRoundRobin
	switch strings.ToLower(cfg.Strategy) {
	case "least_conn":
		strat = woos.StLeastConn
	case "random":
		strat = woos.StRandom
	}

	return &TCPBalancer{
		backends: backends,
		strategy: int(strat),
	}
}

func (tb *TCPBalancer) Pick() *TCPBackend {
	if len(tb.backends) == 0 {
		return nil
	}
	if len(tb.backends) == 1 {
		return tb.backends[0]
	}

	switch tb.strategy {
	case int(woos.StLeastConn):
		return tb.pickLeastConn()
	case int(woos.StRandom):
		return tb.pickRandom()
	default:
		return tb.pickRoundRobin()
	}
}

func (tb *TCPBalancer) pickRoundRobin() *TCPBackend {
	n := uint64(len(tb.backends))
	idx := tb.rrCounter.Add(1) % n
	return tb.backends[idx]
}

func (tb *TCPBalancer) pickRandom() *TCPBackend {
	var seed uint64
	binary.Read(rand.Reader, binary.LittleEndian, &seed)
	idx := seed % uint64(len(tb.backends))
	return tb.backends[idx]
}

func (tb *TCPBalancer) pickLeastConn() *TCPBackend {
	var best *TCPBackend
	var min int64 = math.MaxInt64

	for _, b := range tb.backends {
		c := b.ActiveConns.Load()
		if c < min {
			min = c
			best = b
		}
	}
	return best
}
