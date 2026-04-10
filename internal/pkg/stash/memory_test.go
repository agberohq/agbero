package stash

import (
	"net/http"
	"testing"
	"time"
)

func TestMemoryStoreBasic(t *testing.T) {
	cfg := &Config{
		Driver:     "memory",
		DefaultTTL: 5 * time.Minute,
		MaxItems:   100,
	}

	store, err := NewStore(cfg)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	entry := &Entry{
		Body:        []byte("test body"),
		Headers:     http.Header{"Content-Type": []string{"text/plain"}},
		Status:      http.StatusOK,
		ContentType: "text/plain",
		CreatedAt:   time.Now(),
	}

	key := "test-key"
	store.Set(key, entry, time.Minute)

	got, ok := store.Get(key)
	if !ok {
		t.Fatal("expected to get entry")
	}

	if string(got.Body) != string(entry.Body) {
		t.Errorf("expected body %q, got %q", entry.Body, got.Body)
	}
}

func TestMemoryStoreExpiration(t *testing.T) {
	cfg := &Config{
		Driver:     "memory",
		DefaultTTL: 5 * time.Minute,
		MaxItems:   100,
	}

	store, err := NewStore(cfg)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	entry := &Entry{
		Body:      []byte("test body"),
		Headers:   http.Header{},
		Status:    http.StatusOK,
		CreatedAt: time.Now(),
	}

	key := "expire-key"
	store.Set(key, entry, 100*time.Millisecond)

	if _, ok := store.Get(key); !ok {
		t.Error("entry should exist immediately")
	}

	time.Sleep(200 * time.Millisecond)

	if _, ok := store.Get(key); ok {
		t.Error("entry should have expired")
	}
}

func TestMemoryStoreDelete(t *testing.T) {
	cfg := &Config{
		Driver:     "memory",
		DefaultTTL: 5 * time.Minute,
		MaxItems:   100,
	}

	store, err := NewStore(cfg)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	entry := &Entry{
		Body:      []byte("test body"),
		Headers:   http.Header{},
		Status:    http.StatusOK,
		CreatedAt: time.Now(),
	}

	key := "delete-key"
	store.Set(key, entry, time.Minute)

	if _, ok := store.Get(key); !ok {
		t.Error("entry should exist")
	}

	store.Delete(key)

	if _, ok := store.Get(key); ok {
		t.Error("entry should be deleted")
	}
}

func TestMemoryStoreClear(t *testing.T) {
	cfg := &Config{
		Driver:     "memory",
		DefaultTTL: 5 * time.Minute,
		MaxItems:   100,
	}

	store, err := NewStore(cfg)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	for i := 0; i < 10; i++ {
		entry := &Entry{
			Body:      []byte("test body"),
			Headers:   http.Header{},
			Status:    http.StatusOK,
			CreatedAt: time.Now(),
		}
		store.Set(string(rune(i+48)), entry, time.Minute)
	}

	store.Clear()

	for i := 0; i < 10; i++ {
		if _, ok := store.Get(string(rune(i + 48))); ok {
			t.Errorf("key %d should be cleared", i)
		}
	}
}

func TestMemoryStoreSetWithPolicy(t *testing.T) {
	cfg := &Config{
		Driver:     "memory",
		DefaultTTL: 10 * time.Minute,
		MaxItems:   100,
		Policy:     nil,
	}

	store, err := NewStore(cfg)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	entry := &Entry{
		Body:        []byte("test body"),
		Headers:     http.Header{},
		Status:      http.StatusOK,
		ContentType: "text/html",
		CreatedAt:   time.Now(),
	}

	key := "policy-key"
	store.SetWithPolicy(key, entry, nil, cfg.DefaultTTL)

	if _, ok := store.Get(key); !ok {
		t.Error("entry should exist after SetWithPolicy")
	}
}

func TestMemoryStoreZeroTTL(t *testing.T) {
	cfg := &Config{
		Driver:     "memory",
		DefaultTTL: 5 * time.Minute,
		MaxItems:   100,
	}

	store, err := NewStore(cfg)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	entry := &Entry{
		Body:      []byte("test body"),
		Headers:   http.Header{},
		Status:    http.StatusOK,
		CreatedAt: time.Now(),
	}

	key := "zero-ttl"
	store.Set(key, entry, 0)

	if _, ok := store.Get(key); ok {
		t.Error("entry with zero TTL should not be stored")
	}
}
