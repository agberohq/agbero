package cluster

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/olekukonko/ll"
)

var (
	logger = ll.New("test").Disable()
)

// newTestDelegate returns a minimal delegate suitable for unit tests.
// No handler, cipher, queue, or configMgr are wired — tests that need
// them should set fields directly on the returned struct.
func newTestDelegate() *delegate {
	return newDelegate(nil, logger, &RealMetrics{}, nil, nil)
}

// envelope builds a test Envelope with the given key, op, and timestamp offset
// from now. A positive offset produces a future timestamp; negative is in the past.
func envelope(key string, op OpType, offset time.Duration) Envelope {
	return Envelope{
		Key:       key,
		Op:        op,
		Value:     []byte("v"),
		Timestamp: time.Now().Add(offset).UnixNano(),
	}
}

// --------------------------------------------------------------------------
// SEC-06 — stale envelope rejection
// --------------------------------------------------------------------------

// TestApply_StaleEnvelope_Rejected verifies that an envelope older than
// tombstoneTTL is discarded even when the delegate store is empty (no existing
// state to compare against). This prevents a replayed 25-hour-old state dump
// from being accepted in full during a node join.
func TestApply_StaleEnvelope_Rejected(t *testing.T) {
	d := newTestDelegate()

	stale := Envelope{
		Key:       "route:example.com",
		Op:        OpSet,
		Value:     []byte(`{"path":"/"}`),
		Timestamp: time.Now().Add(-25 * time.Hour).UnixNano(),
	}

	d.apply(stale, false)

	d.mu.RLock()
	_, stored := d.store[stale.Key]
	d.mu.RUnlock()

	if stored {
		t.Error("stale envelope (25h old) must not be stored on a fresh delegate")
	}
}

// TestApply_StaleEnvelope_ExactBoundary checks that an envelope exactly at
// tombstoneTTL is also rejected (age > tombstoneTTL is exclusive).
func TestApply_StaleEnvelope_ExactBoundary(t *testing.T) {
	d := newTestDelegate()

	env := Envelope{
		Key:       "route:boundary",
		Op:        OpSet,
		Value:     []byte("v"),
		Timestamp: time.Now().Add(-(tombstoneTTL + time.Second)).UnixNano(),
	}
	d.apply(env, false)

	d.mu.RLock()
	_, stored := d.store[env.Key]
	d.mu.RUnlock()

	if stored {
		t.Error("envelope beyond tombstoneTTL must be rejected")
	}
}

// TestApply_FreshEnvelope_Accepted verifies that a recent envelope is stored
// on a fresh delegate — confirming the stale check does not over-reject.
func TestApply_FreshEnvelope_Accepted(t *testing.T) {
	d := newTestDelegate()

	env := envelope("route:example.com", OpSet, -1*time.Minute)
	d.apply(env, false)

	d.mu.RLock()
	_, stored := d.store[env.Key]
	d.mu.RUnlock()

	if !stored {
		t.Error("fresh envelope must be accepted and stored")
	}
}

// TestMergeRemoteState_StaleRejected verifies the stale check fires when
// envelopes arrive via MergeRemoteState (node join path), which is the exact
// attack vector SEC-06 protects against.
func TestMergeRemoteState_StaleRejected(t *testing.T) {
	d := newTestDelegate()

	stale := Envelope{
		Key:       "route:joined",
		Op:        OpSet,
		Value:     []byte("v"),
		Timestamp: time.Now().Add(-25 * time.Hour).UnixNano(),
	}
	buf, _ := json.Marshal(map[string]Envelope{stale.Key: stale})

	d.MergeRemoteState(buf, true)

	d.mu.RLock()
	_, stored := d.store[stale.Key]
	d.mu.RUnlock()

	if stored {
		t.Error("stale envelope via MergeRemoteState must not be stored")
	}
}

// --------------------------------------------------------------------------
// Existing apply logic
// --------------------------------------------------------------------------

// TestApply_NewerTimestampWins verifies that a newer envelope for the same
// key replaces an older one.
func TestApply_NewerTimestampWins(t *testing.T) {
	d := newTestDelegate()

	old := envelope("route:x", OpSet, -10*time.Minute)
	d.apply(old, false)

	newer := envelope("route:x", OpSet, -1*time.Minute)
	newer.Value = []byte("newer")
	d.apply(newer, false)

	d.mu.RLock()
	stored := d.store["route:x"]
	d.mu.RUnlock()

	if string(stored.Value) != "newer" {
		t.Errorf("newer envelope must win, got %q", string(stored.Value))
	}
}

// TestApply_OlderTimestampIgnored verifies that an older envelope for the
// same key does not overwrite a newer one already in the store.
func TestApply_OlderTimestampIgnored(t *testing.T) {
	d := newTestDelegate()

	newer := envelope("route:x", OpSet, -1*time.Minute)
	newer.Value = []byte("newer")
	d.apply(newer, false)

	old := envelope("route:x", OpSet, -10*time.Minute)
	old.Value = []byte("old")
	d.apply(old, false)

	d.mu.RLock()
	stored := d.store["route:x"]
	d.mu.RUnlock()

	if string(stored.Value) != "newer" {
		t.Errorf("older envelope must not overwrite newer, got %q", string(stored.Value))
	}
}

// TestApply_Delete_NilsValue verifies that OpDel sets Value to nil in the store.
func TestApply_Delete_NilsValue(t *testing.T) {
	d := newTestDelegate()

	set := envelope("route:x", OpSet, -2*time.Minute)
	d.apply(set, false)

	del := envelope("route:x", OpDel, -1*time.Minute)
	d.apply(del, false)

	d.mu.RLock()
	stored := d.store["route:x"]
	d.mu.RUnlock()

	if stored.Value != nil {
		t.Errorf("OpDel must nil out Value, got %v", stored.Value)
	}
	if stored.Op != OpDel {
		t.Errorf("stored Op must be OpDel, got %v", stored.Op)
	}
}

// TestApply_Lock_ExistingLockExpired verifies that an expired lock can be
// replaced by a new one.
func TestApply_Lock_ExistingLockExpired(t *testing.T) {
	d := newTestDelegate()

	expired := Envelope{
		Key:       "lock:renew:example.com",
		Op:        OpLock,
		Value:     []byte("v"),
		Timestamp: time.Now().Add(-(lockTTL + time.Second)).UnixNano(),
	}
	d.mu.Lock()
	d.store[expired.Key] = expired
	d.mu.Unlock()

	fresh := envelope("lock:renew:example.com", OpLock, -1*time.Second)
	fresh.Value = []byte("new-owner")
	d.apply(fresh, false)

	d.mu.RLock()
	stored := d.store[fresh.Key]
	d.mu.RUnlock()

	if string(stored.Value) != "new-owner" {
		t.Errorf("expired lock must be replaceable, got %q", string(stored.Value))
	}
}

// TestApply_EmptyBuffer_Ignored verifies MergeRemoteState is a no-op on empty input.
func TestApply_EmptyBuffer_Ignored(t *testing.T) {
	d := newTestDelegate()
	d.MergeRemoteState([]byte{}, true)

	d.mu.RLock()
	count := len(d.store)
	d.mu.RUnlock()

	if count != 0 {
		t.Errorf("empty buffer must not add any entries, got %d", count)
	}
}

// TestPruneTombstones removes stale OpDel entries from the store.
func TestPruneTombstones(t *testing.T) {
	d := newTestDelegate()

	staleKey := "route:stale"
	d.mu.Lock()
	d.store[staleKey] = Envelope{
		Key:       staleKey,
		Op:        OpDel,
		Timestamp: time.Now().Add(-(tombstoneTTL + time.Second)).UnixNano(),
	}
	d.mu.Unlock()

	d.pruneTombstones()

	d.mu.RLock()
	_, still := d.store[staleKey]
	d.mu.RUnlock()

	if still {
		t.Error("pruneTombstones must remove expired OpDel entries")
	}
}
