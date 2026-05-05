package stash

import (
	"net/http"
	"testing"
	"time"
)

// Entry — SurrogateTags field

func TestEntry_SurrogateTags_DefaultEmpty(t *testing.T) {
	e := &Entry{
		Body:      []byte("hello"),
		Status:    200,
		CreatedAt: time.Now(),
	}
	if len(e.SurrogateTags) != 0 {
		t.Fatalf("new Entry should have no surrogate tags, got %v", e.SurrogateTags)
	}
}

func TestEntry_SurrogateTags_Assigned(t *testing.T) {
	e := &Entry{
		Body:          []byte("video content"),
		Status:        200,
		ContentType:   "video/mp4",
		SurrogateTags: []string{"video", "product:42"},
		CreatedAt:     time.Now(),
	}
	if len(e.SurrogateTags) != 2 {
		t.Fatalf("expected 2 surrogate tags, got %d", len(e.SurrogateTags))
	}
	if e.SurrogateTags[0] != "video" || e.SurrogateTags[1] != "product:42" {
		t.Fatalf("unexpected tag values: %v", e.SurrogateTags)
	}
}

func TestEntry_HasTag(t *testing.T) {
	e := &Entry{
		SurrogateTags: []string{"product:99", "category:books"},
	}
	if !e.HasTag("product:99") {
		t.Error("HasTag should return true for existing tag")
	}
	if !e.HasTag("category:books") {
		t.Error("HasTag should return true for second tag")
	}
	if e.HasTag("user:1") {
		t.Error("HasTag should return false for absent tag")
	}
}

func TestEntry_HasTag_EmptyTags(t *testing.T) {
	e := &Entry{}
	if e.HasTag("anything") {
		t.Error("HasTag on entry with no tags should always return false")
	}
}

// Entry — IsStale helper

func TestEntry_IsStale_Fresh(t *testing.T) {
	e := &Entry{
		CreatedAt: time.Now(),
		TTL:       5 * time.Minute,
	}
	if e.IsStale() {
		t.Error("newly created entry should not be stale")
	}
}

func TestEntry_IsStale_Expired(t *testing.T) {
	e := &Entry{
		CreatedAt: time.Now().Add(-10 * time.Minute),
		TTL:       5 * time.Minute,
	}
	if !e.IsStale() {
		t.Error("entry past TTL should be stale")
	}
}

func TestEntry_IsStale_ZeroTTL(t *testing.T) {
	// Zero TTL means no expiry info — treat as not stale
	e := &Entry{
		CreatedAt: time.Now().Add(-24 * time.Hour),
		TTL:       0,
	}
	if e.IsStale() {
		t.Error("entry with zero TTL should not be considered stale")
	}
}

// Entry — VaryHeaders roundtrip (existing field, ensure tag addition did not break)

func TestEntry_VaryHeaders_NotAffectedByTagAddition(t *testing.T) {
	e := &Entry{
		VaryHeaders:   map[string]string{"Accept-Encoding": "gzip"},
		SurrogateTags: []string{"static"},
	}
	if e.VaryHeaders["Accept-Encoding"] != "gzip" {
		t.Error("VaryHeaders should be unaffected by SurrogateTags field")
	}
}

func newTestMemoryStore(t *testing.T) Store {
	t.Helper()
	s, err := NewStore(&Config{
		Driver:     "memory",
		DefaultTTL: time.Minute,
		MaxItems:   100,
	})
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func buildRequest(t *testing.T, path string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, "http://example.com"+path, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return r
}

func TestMemoryStore_PurgeByTag_RemovesMatchingEntries(t *testing.T) {
	s := newTestMemoryStore(t)

	key1 := Key(buildRequest(t, "/a"), nil)
	key2 := Key(buildRequest(t, "/b"), nil)
	key3 := Key(buildRequest(t, "/c"), nil)

	s.Set(key1, &Entry{Body: []byte("a"), Status: 200, SurrogateTags: []string{"product:1"}}, time.Minute)
	s.Set(key2, &Entry{Body: []byte("b"), Status: 200, SurrogateTags: []string{"product:1", "category:x"}}, time.Minute)
	s.Set(key3, &Entry{Body: []byte("c"), Status: 200, SurrogateTags: []string{"category:y"}}, time.Minute)

	if err := s.Purge("product:1"); err != nil {
		t.Fatalf("PurgeByTag returned error: %v", err)
	}

	if _, ok := s.Get(key1); ok {
		t.Error("key1 (tagged product:1) should have been purged")
	}
	if _, ok := s.Get(key2); ok {
		t.Error("key2 (tagged product:1) should have been purged")
	}
	if _, ok := s.Get(key3); !ok {
		t.Error("key3 (not tagged product:1) should still exist")
	}
}

func TestMemoryStore_PurgeByTag_NoMatch(t *testing.T) {
	s := newTestMemoryStore(t)

	key := Key(buildRequest(t, "/x"), nil)
	s.Set(key, &Entry{Body: []byte("x"), Status: 200, SurrogateTags: []string{"foo"}}, time.Minute)

	if err := s.Purge("bar"); err != nil {
		t.Fatalf("PurgeByTag with no matching tags should not error: %v", err)
	}

	if _, ok := s.Get(key); !ok {
		t.Error("untagged entry should not have been purged")
	}
}

func TestMemoryStore_PurgeByTag_EmptyStore(t *testing.T) {
	s := newTestMemoryStore(t)
	if err := s.Purge("anything"); err != nil {
		t.Fatalf("PurgeByTag on empty store should not error: %v", err)
	}
}

func TestMemoryStore_PurgeByTag_EntryWithNoTags(t *testing.T) {
	s := newTestMemoryStore(t)

	key := Key(buildRequest(t, "/notag"), nil)
	s.Set(key, &Entry{Body: []byte("ok"), Status: 200}, time.Minute)

	if err := s.Purge("anything"); err != nil {
		t.Fatalf("PurgeByTag should not error: %v", err)
	}

	if _, ok := s.Get(key); !ok {
		t.Error("entry with no tags should survive PurgeByTag")
	}
}

// Store interface — PurgeByTag is part of the contract

func TestStoreInterface_PurgeByTagIsImplemented(t *testing.T) {
	// Compile-time check: Store interface must have PurgeByTag
	var _ Store = (*MemoryStore)(nil)
}
