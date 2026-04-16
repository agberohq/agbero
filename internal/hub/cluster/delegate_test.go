package cluster

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/olekukonko/ll"
)

var (
	logger = ll.New("test").Disable()
)

// newTestDelegate returns a minimal delegate suitable for unit tests.
// No handler, cipher, queue, configMgr, or keeper callbacks are wired —
// tests that need them pass a Config with the relevant fields set.
func newTestDelegate() *delegate {
	return newDelegate(Config{}, nil, logger, &RealMetrics{}, nil, nil)
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
// attack vector SEC-06 protects against. Uses the legacy flat-map wire format
// to confirm backward compatibility is also covered.
func TestMergeRemoteState_StaleRejected(t *testing.T) {
	d := newTestDelegate()

	stale := Envelope{
		Key:       "route:joined",
		Op:        OpSet,
		Value:     []byte("v"),
		Timestamp: time.Now().Add(-25 * time.Hour).UnixNano(),
	}
	// Legacy flat-map format — pre-OpSecret nodes send this.
	buf, _ := json.Marshal(map[string]Envelope{stale.Key: stale})

	d.MergeRemoteState(buf, true)

	d.mu.RLock()
	_, stored := d.store[stale.Key]
	d.mu.RUnlock()

	if stored {
		t.Error("stale envelope via MergeRemoteState must not be stored")
	}
}

// Existing apply logic

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

// OpSecret / keeper sync

// TestLocalState_NoSecrets_WhenNotJoin verifies that LocalState does not
// include any secrets payload when join=false (periodic full-state exchange).
func TestLocalState_NoSecrets_WhenNotJoin(t *testing.T) {
	called := false
	cipher, _ := security.NewCipher("12345678901234567890123456789012")
	cfg := Config{
		KeeperSnapshot: func() map[string][]byte {
			called = true
			return map[string][]byte{"vault://key/cluster": []byte("secret")}
		},
	}
	d := newDelegate(cfg, nil, logger, &RealMetrics{}, cipher, nil)

	_ = d.LocalState(false)

	if called {
		t.Error("keeperSnapshot must not be called when join=false")
	}
}

// TestLocalState_IncludesSecrets_WhenJoin verifies that LocalState includes
// encrypted OpSecret envelopes when join=true and both cipher and
// keeperSnapshot are set.
func TestLocalState_IncludesSecrets_WhenJoin(t *testing.T) {
	secretVal := []byte("my-secret-value")
	cipher, _ := security.NewCipher("12345678901234567890123456789012")

	cfg := Config{
		KeeperSnapshot: func() map[string][]byte {
			return map[string][]byte{"vault://key/internal": append([]byte(nil), secretVal...)}
		},
	}
	d := newDelegate(cfg, nil, logger, &RealMetrics{}, cipher, nil)

	buf := d.LocalState(true)

	type stateDoc struct {
		Store   map[string]Envelope `json:"store"`
		Secrets []Envelope          `json:"secrets,omitempty"`
	}
	var doc stateDoc
	if err := json.Unmarshal(buf, &doc); err != nil {
		t.Fatalf("LocalState output is not valid JSON: %v", err)
	}
	if len(doc.Secrets) != 1 {
		t.Fatalf("expected 1 secret envelope, got %d", len(doc.Secrets))
	}

	env := doc.Secrets[0]
	if env.Op != OpSecret {
		t.Errorf("secret envelope Op must be OpSecret, got %d", env.Op)
	}
	if env.Key != "vault://key/internal" {
		t.Errorf("secret envelope Key mismatch: got %q", env.Key)
	}

	// Value must be encrypted — not the raw plaintext.
	if string(env.Value) == string(secretVal) {
		t.Error("secret envelope Value must be ciphertext, not plaintext")
	}

	// Decrypt and verify.
	plain, err := cipher.Decrypt(env.Value)
	if err != nil {
		t.Fatalf("could not decrypt secret envelope: %v", err)
	}
	if string(plain) != string(secretVal) {
		t.Errorf("decrypted value mismatch: got %q, want %q", plain, secretVal)
	}
}

// TestLocalState_NoCipher_SkipsSecrets verifies that when cipher is nil
// (no secret_key configured), the secrets block is omitted even on join.
func TestLocalState_NoCipher_SkipsSecrets(t *testing.T) {
	called := false
	cfg := Config{
		KeeperSnapshot: func() map[string][]byte {
			called = true
			return map[string][]byte{"vault://key/cluster": []byte("secret")}
		},
	}
	// cipher intentionally nil
	d := newDelegate(cfg, nil, logger, &RealMetrics{}, nil, nil)

	buf := d.LocalState(true)

	type stateDoc struct {
		Secrets []Envelope `json:"secrets,omitempty"`
	}
	var doc stateDoc
	json.Unmarshal(buf, &doc)

	if called {
		t.Error("keeperSnapshot must not be called when cipher is nil")
	}
	if len(doc.Secrets) != 0 {
		t.Errorf("expected no secrets when cipher is nil, got %d", len(doc.Secrets))
	}
}

// TestMergeRemoteState_AppliesSecrets verifies that the joining node
// decrypts OpSecret envelopes and writes them to the keeper via keeperWrite.
func TestMergeRemoteState_AppliesSecrets(t *testing.T) {
	cipher, _ := security.NewCipher("12345678901234567890123456789012")
	secretKey := "vault://key/internal"
	secretVal := []byte("ppk-pem-data")

	encrypted, err := cipher.Encrypt(secretVal)
	if err != nil {
		t.Fatalf("failed to encrypt test secret: %v", err)
	}

	var mu sync.Mutex
	written := make(map[string][]byte)

	cfg := Config{
		KeeperWrite: func(key string, value []byte) {
			mu.Lock()
			written[key] = append([]byte(nil), value...)
			mu.Unlock()
		},
	}
	d := newDelegate(cfg, nil, logger, &RealMetrics{}, cipher, nil)

	type stateDoc struct {
		Store   map[string]Envelope `json:"store"`
		Secrets []Envelope          `json:"secrets,omitempty"`
	}
	doc := stateDoc{
		Store: map[string]Envelope{},
		Secrets: []Envelope{
			{Op: OpSecret, Key: secretKey, Value: encrypted, Timestamp: time.Now().UnixNano()},
		},
	}
	buf, _ := json.Marshal(doc)

	d.MergeRemoteState(buf, true)

	mu.Lock()
	got, ok := written[secretKey]
	mu.Unlock()

	if !ok {
		t.Fatal("keeperWrite was not called for the synced secret")
	}
	if string(got) != string(secretVal) {
		t.Errorf("keeperWrite received wrong value: got %q, want %q", got, secretVal)
	}

	// OpSecret envelopes must NOT be stored in the gossip state map.
	d.mu.RLock()
	_, inStore := d.store[secretKey]
	d.mu.RUnlock()
	if inStore {
		t.Error("OpSecret envelope must not persist in the gossip store")
	}
}

// TestMergeRemoteState_NilKeeperWrite_DropsSecrets verifies that when
// keeperWrite is nil (seed node receiving its own join broadcast), incoming
// OpSecret envelopes are silently dropped — not panicked on.
func TestMergeRemoteState_NilKeeperWrite_DropsSecrets(t *testing.T) {
	cipher, _ := security.NewCipher("12345678901234567890123456789012")
	encrypted, _ := cipher.Encrypt([]byte("secret"))

	// keeperWrite intentionally absent
	d := newDelegate(Config{}, nil, logger, &RealMetrics{}, cipher, nil)

	type stateDoc struct {
		Store   map[string]Envelope `json:"store"`
		Secrets []Envelope          `json:"secrets,omitempty"`
	}
	doc := stateDoc{
		Secrets: []Envelope{
			{Op: OpSecret, Key: "vault://key/cluster", Value: encrypted, Timestamp: time.Now().UnixNano()},
		},
	}
	buf, _ := json.Marshal(doc)

	// Must not panic.
	d.MergeRemoteState(buf, true)
}

// TestMergeRemoteState_NilCipher_DropsSecrets verifies that when cipher is
// nil (no secret_key on the joining node's config), OpSecret envelopes are
// dropped with a warning and no panic.
func TestMergeRemoteState_NilCipher_DropsSecrets(t *testing.T) {
	// Manually build a valid ciphertext using a separate cipher so the
	// envelope looks real, but the receiving delegate has no cipher.
	tmpCipher, _ := security.NewCipher("12345678901234567890123456789012")
	encrypted, _ := tmpCipher.Encrypt([]byte("secret"))

	d := newDelegate(Config{}, nil, logger, &RealMetrics{}, nil, nil)

	type stateDoc struct {
		Store   map[string]Envelope `json:"store"`
		Secrets []Envelope          `json:"secrets,omitempty"`
	}
	doc := stateDoc{
		Secrets: []Envelope{
			{Op: OpSecret, Key: "vault://key/cluster", Value: encrypted, Timestamp: time.Now().UnixNano()},
		},
	}
	buf, _ := json.Marshal(doc)

	// Must not panic.
	d.MergeRemoteState(buf, true)
}

// TestMergeRemoteState_LegacyFlatMap_BackwardCompat verifies that a state
// blob in the pre-OpSecret flat-map format is still correctly applied.
// This covers rolling upgrades where older nodes are still in the cluster.
func TestMergeRemoteState_LegacyFlatMap_BackwardCompat(t *testing.T) {
	d := newTestDelegate()

	env := Envelope{
		Key:       "route:legacy",
		Op:        OpSet,
		Value:     []byte("old-format"),
		Timestamp: time.Now().Add(-1 * time.Minute).UnixNano(),
	}
	// Old format: flat map, no "store" wrapper.
	buf, _ := json.Marshal(map[string]Envelope{env.Key: env})

	d.MergeRemoteState(buf, false)

	val, ok := d.get("route:legacy")
	if !ok || string(val) != "old-format" {
		t.Errorf("legacy flat-map format must still be applied, got ok=%v val=%q", ok, val)
	}
}

// TestLocalState_PlaintextNotLeaked verifies that after LocalState(true)
// returns, none of the snapshot map values remain readable as plaintext
// in the returned JSON blob.
func TestLocalState_PlaintextNotLeaked(t *testing.T) {
	plain := []byte("super-secret-ppk-pem")
	cipher, _ := security.NewCipher("12345678901234567890123456789012")

	cfg := Config{
		KeeperSnapshot: func() map[string][]byte {
			return map[string][]byte{"vault://key/internal": append([]byte(nil), plain...)}
		},
	}
	d := newDelegate(cfg, nil, logger, &RealMetrics{}, cipher, nil)

	buf := d.LocalState(true)

	// The raw plaintext must not appear verbatim anywhere in the output.
	if containsSubslice(buf, plain) {
		t.Error("LocalState output must not contain plaintext secret value")
	}
}

// containsSubslice reports whether needle appears verbatim in haystack.
func containsSubslice(haystack, needle []byte) bool {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return false
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
