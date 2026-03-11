package xtcp

import (
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/pkg/metrics"
)

func TestBalancer_Pick_RetryDistribution(t *testing.T) {
	backends := []alaye.Server{
		{Address: "127.0.0.1:8001"},
		{Address: "127.0.0.1:8002"},
		{Address: "127.0.0.1:8003"},
	}

	route := alaye.TCPRoute{
		Strategy: "hash",
		Backends: backends,
	}

	bal := NewBalancer(route, metrics.NewRegistry())

	selections := make(map[string]int)
	for i := 0; i < 100; i++ {
		be := bal.Pick(nil)
		if be != nil {
			selections[be.Address]++
		}
	}

	if len(selections) < 2 {
		t.Errorf("Expected distribution across multiple backends, got %d unique backends", len(selections))
	}

	for addr, count := range selections {
		if count == 100 {
			t.Errorf("All requests went to same backend %s, retry randomization not working", addr)
		}
	}
}

func TestBalancer_Pick_ExcludesDeadBackends(t *testing.T) {
	backends := []alaye.Server{
		{Address: "127.0.0.1:8001"},
		{Address: "127.0.0.1:8002"},
	}

	route := alaye.TCPRoute{
		Strategy: "round_robin",
		Backends: backends,
	}

	bal := NewBalancer(route, metrics.NewRegistry())

	be := bal.Backends()[0]
	be.Status(false)

	exclude := map[*Backend]struct{}{be: {}}

	picked := bal.Pick(exclude)
	if picked == be {
		t.Error("Pick should not return excluded dead backend")
	}

	if picked == nil {
		t.Error("Pick should return the other available backend")
	}
}
