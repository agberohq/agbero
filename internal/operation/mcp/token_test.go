package mcp

import (
	"sync"
	"testing"
	"time"

	"github.com/agberohq/keeper"
)

type fakeKeeper struct {
	mu     sync.Mutex
	data   map[string][]byte
	locked bool
}

func newFakeKeeper() *fakeKeeper {
	return &fakeKeeper{data: make(map[string][]byte)}
}

func (f *fakeKeeper) Get(key string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.locked {
		return nil, ErrKeeperLocked
	}
	v, ok := f.data[key]
	if !ok {
		return nil, keeper.ErrKeyNotFound
	}
	return append([]byte(nil), v...), nil
}

func (f *fakeKeeper) Set(key string, value []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.locked {
		return ErrKeeperLocked
	}
	f.data[key] = append([]byte(nil), value...)
	return nil
}

func (f *fakeKeeper) IsLocked() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.locked
}

func TestTokenMintVerify(t *testing.T) {
	store := NewTokenStore(newFakeKeeper())
	raw, claims, err := store.Mint("alice", []string{ScopeRead}, time.Hour)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if claims.Subject != "alice" || claims.ID == "" {
		t.Fatalf("claims = %+v", claims)
	}
	got, err := store.Verify(raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Subject != "alice" || !HasScope(got, ScopeRead) {
		t.Fatalf("verified claims = %+v", got)
	}
}

func TestTokenPlanImpliesRead(t *testing.T) {
	store := NewTokenStore(newFakeKeeper())
	raw, _, err := store.Mint("alice", []string{ScopePlan}, time.Hour)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	got, err := store.Verify(raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !HasScope(got, ScopeRead) || !HasScope(got, ScopePlan) {
		t.Fatalf("scope = %q; want read+plan", got.Scope)
	}
}

func TestTokenRejectsApply(t *testing.T) {
	store := NewTokenStore(newFakeKeeper())
	if _, _, err := store.Mint("alice", []string{"mcp:apply"}, time.Hour); err == nil {
		t.Fatal("Mint accepted mcp:apply")
	}
}

func TestTokenKeeperLocked(t *testing.T) {
	f := newFakeKeeper()
	store := NewTokenStore(f)
	if err := store.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	raw, _, err := store.Mint("alice", []string{ScopeRead}, time.Hour)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	f.locked = true
	if err := store.Ensure(); err != ErrKeeperLocked {
		t.Fatalf("Ensure locked err = %v, want ErrKeeperLocked", err)
	}
	if _, err := store.Verify(raw); err != ErrKeeperLocked {
		t.Fatalf("Verify locked err = %v, want ErrKeeperLocked", err)
	}
}

func TestTokenRotation(t *testing.T) {
	store := NewTokenStore(newFakeKeeper())
	oldToken, _, err := store.Mint("alice", []string{ScopeRead}, time.Hour)
	if err != nil {
		t.Fatalf("Mint old: %v", err)
	}
	if err := store.Rotate(); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if _, err := store.Verify(oldToken); err != nil {
		t.Fatalf("old token should verify against previous key: %v", err)
	}
	newToken, _, err := store.Mint("alice", []string{ScopeRead}, time.Hour)
	if err != nil {
		t.Fatalf("Mint new: %v", err)
	}
	if _, err := store.Verify(newToken); err != nil {
		t.Fatalf("new token: %v", err)
	}
	if err := store.Rotate(); err != nil {
		t.Fatalf("second Rotate: %v", err)
	}
	if _, err := store.Verify(oldToken); err == nil {
		t.Fatal("old token verified after the previous key was retired")
	}
}

func TestTokenTampered(t *testing.T) {
	store := NewTokenStore(newFakeKeeper())
	raw, _, err := store.Mint("alice", []string{ScopeRead}, time.Hour)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := store.Verify(raw + "x"); err == nil {
		t.Fatal("tampered token verified")
	}
}

func TestEnsureCreatesKey(t *testing.T) {
	f := newFakeKeeper()
	store := NewTokenStore(f)
	if err := store.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	key, err := f.Get(tokenKeyPath)
	if err != nil {
		t.Fatalf("Get token key: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("key length = %d, want 32", len(key))
	}
}

func TestTokenTTL(t *testing.T) {
	store := NewTokenStore(newFakeKeeper())
	if _, _, err := store.Mint("alice", []string{ScopeRead}, 25*time.Hour); err == nil {
		t.Fatal("Mint accepted a TTL over 24h")
	}
	if _, _, err := store.Mint("alice", []string{ScopeRead}, 0); err != nil {
		t.Fatalf("Mint zero TTL should use the default: %v", err)
	}
}
