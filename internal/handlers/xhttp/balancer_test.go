package xhttp

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"git.imaxinacion.net/aibox/agbero/internal/core/metrics"
)

func makeBackend(weight int, alive bool) *Backend {
	// 1. Initialize the atomic bool pointer
	ab := &atomic.Bool{}
	ab.Store(alive)

	b := &Backend{
		Weight:   weight,
		Activity: &metrics.Activity{},
		Alive:    ab, // 2. Assign the pointer
	}
	return b
}

func TestLoadBalancer_RoundRobin(t *testing.T) {
	b1 := makeBackend(1, true)
	b2 := makeBackend(1, true)
	b3 := makeBackend(1, true)

	lb := NewLoadBalancer(
		[]*Backend{b1, b2, b3},
		"round_robin",
		0,
		nil,
	)

	seen := map[*Backend]int{}

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	for i := 0; i < 300; i++ {
		b := lb.PickBackend(req)
		if b == nil {
			t.Fatal("unexpected nil backend")
		}
		seen[b]++
	}

	if len(seen) != 3 {
		t.Fatalf("expected 3 backends, got %d", len(seen))
	}
}

func TestLoadBalancer_SkipDeadBackend(t *testing.T) {
	b1 := makeBackend(1, false)
	b2 := makeBackend(1, true)

	lb := NewLoadBalancer(
		[]*Backend{b1, b2},
		"round_robin",
		0,
		nil,
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	b := lb.PickBackend(req)

	if b != b2 {
		t.Fatalf("expected alive backend, got %+v", b)
	}
}

func TestLoadBalancer_LeastConn(t *testing.T) {
	b1 := makeBackend(1, true)
	b2 := makeBackend(1, true)

	b1.Activity.InFlight.Store(10)
	b2.Activity.InFlight.Store(2)

	lb := NewLoadBalancer(
		[]*Backend{b1, b2},
		"least_conn",
		0,
		nil,
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	b := lb.PickBackend(req)

	if b != b2 {
		t.Fatalf("expected backend with fewer inflight, got %+v", b)
	}
}

func TestLoadBalancer_WeightedLeastConn(t *testing.T) {
	b1 := makeBackend(10, true)
	b2 := makeBackend(1, true)

	b1.Activity.InFlight.Store(10)
	b2.Activity.InFlight.Store(0)

	lb := NewLoadBalancer(
		[]*Backend{b1, b2},
		"weighted_least_conn",
		0,
		nil,
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	b := lb.PickBackend(req)

	if b != b2 {
		t.Fatalf("expected backend b2 (better score), got %+v", b)
	}
}

func TestLoadBalancer_RandomDoesNotPanic(t *testing.T) {
	b1 := makeBackend(1, true)
	b2 := makeBackend(1, true)

	lb := NewLoadBalancer(
		[]*Backend{b1, b2},
		"random",
		0,
		nil,
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	for i := 0; i < 1000; i++ {
		if lb.PickBackend(req) == nil {
			t.Fatal("unexpected nil backend")
		}
	}
}

func TestLoadBalancer_UpdateBackendsAtomic(t *testing.T) {
	b1 := makeBackend(1, true)
	b2 := makeBackend(1, true)
	b3 := makeBackend(1, true)

	lb := NewLoadBalancer(
		[]*Backend{b1},
		"round_robin",
		0,
		nil,
	)

	lb.Update([]*Backend{b1, b2, b3})

	snap := lb.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("expected 3 backends, got %d", len(snap))
	}
}
