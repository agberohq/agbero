package metrics

import (
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
)

// TestRegistrySnapshot guards the accessor used by the telemetry collector: it
// must return every registered key with its stats and must not expose the
// registry's internal map (writes to the returned map must not leak back).
func TestRegistrySnapshot(t *testing.T) {
	r := NewRegistry()

	k1 := alaye.Key{Protocol: "http", Domain: "a.example", Path: "/", Addr: "127.0.0.1:9001"}
	k2 := alaye.Key{Protocol: "http", Domain: "b.example", Path: "/", Addr: "127.0.0.1:9002"}
	s1 := r.GetOrRegister(k1)
	s2 := r.GetOrRegister(k2)

	snap := r.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("Snapshot() returned %d entries, want 2", len(snap))
	}
	if snap[k1] != s1 || snap[k2] != s2 {
		t.Fatalf("Snapshot() did not return the registered stats pointers")
	}

	// Mutating the snapshot must not affect the registry.
	delete(snap, k1)
	snap[k2] = nil
	if r.Get(k1) == nil {
		t.Fatalf("deleting from the snapshot removed a live registry entry")
	}
	if r.Get(k2) != s2 {
		t.Fatalf("overwriting a snapshot value changed the registry entry")
	}
}
