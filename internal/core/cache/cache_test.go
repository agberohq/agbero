package cache

import (
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"
)

type testCloserErr struct {
	called atomic.Int64
}

func (c *testCloserErr) Close() error {
	c.called.Add(1)
	return nil
}

type testCloser struct {
	called atomic.Int64
}

func (c *testCloser) Close() {
	c.called.Add(1)
}

func TestCache_Closer_CloseError(t *testing.T) {
	closer := &testCloserErr{}
	it := &Item{Value: closer}

	fn, ok := Closer(it)
	if !ok || fn == nil {
		t.Fatalf("expected closer")
	}

	fn()

	if closer.called.Load() != 1 {
		t.Fatalf("expected Close() error to be called once, got %d", closer.called.Load())
	}
}

func TestCache_Closer_CloseVoid(t *testing.T) {
	closer := &testCloser{}
	it := &Item{Value: closer}

	fn, ok := Closer(it)
	if !ok || fn == nil {
		t.Fatalf("expected closer")
	}

	fn()

	if closer.called.Load() != 1 {
		t.Fatalf("expected Close() to be called once, got %d", closer.called.Load())
	}
}

func TestCache_Closer_NoValue(t *testing.T) {
	_, ok := Closer(nil)
	if ok {
		t.Fatalf("expected ok=false for nil item")
	}

	_, ok = Closer(&Item{})
	if ok {
		t.Fatalf("expected ok=false for nil value")
	}
}

func TestCache_OnDeleteRunsForDelete(t *testing.T) {
	done := make(chan struct{}, 1)
	closer := &testCloserErr{}

	c := New(Options{
		MaximumSize: 10,
		OnDelete: func(key string, it *Item) {
			if key != "k" {
				t.Fatalf("unexpected key: %q", key)
			}
			fn, ok := Closer(it)
			if !ok {
				t.Fatalf("expected closer")
			}
			fn()
			done <- struct{}{}
		},
	})

	c.Store("k", &Item{Value: closer})
	c.Delete("k")

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for OnDelete")
	}

	if closer.called.Load() != 1 {
		t.Fatalf("expected Close() error to be called once, got %d", closer.called.Load())
	}
}

func TestCache_ExpiredItemIsInvalidatedAndOnDeleteRuns(t *testing.T) {
	done := make(chan struct{}, 1)
	closer := &testCloserErr{}

	now := time.Now()
	c := New(Options{
		MaximumSize: 10,
		Now:         func() time.Time { return now },
		OnDelete: func(key string, it *Item) {
			if key != "k" {
				t.Fatalf("unexpected key: %q", key)
			}
			fn, ok := Closer(it)
			if !ok {
				t.Fatalf("expected closer")
			}
			fn()
			done <- struct{}{}
		},
	})

	c.StoreTTL("k", &Item{Value: closer}, 10*time.Millisecond)

	now = now.Add(11 * time.Millisecond)

	if _, ok := c.Load("k"); ok {
		t.Fatalf("expected expired item to be missing")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for OnDelete after expiration")
	}

	if closer.called.Load() != 1 {
		t.Fatalf("expected Close() error to be called once, got %d", closer.called.Load())
	}
}

func TestCache_LoadOrStoreSemantics(t *testing.T) {
	c := New(Options{MaximumSize: 10})

	first := &Item{Value: "v1"}
	got, loaded := c.LoadOrStore("k", first)
	if loaded {
		t.Fatalf("expected loaded=false on first store")
	}
	if got != first {
		t.Fatalf("expected stored item to be returned")
	}

	second := &Item{Value: "v2"}
	got2, loaded2 := c.LoadOrStore("k", second)
	if !loaded2 {
		t.Fatalf("expected loaded=true on cache hit")
	}
	if got2 != first {
		t.Fatalf("expected original item to remain")
	}
}

func TestItem_JSON_LastAccessedRoundTrip(t *testing.T) {
	it := &Item{
		Value: "x",
		Exp:   time.Unix(0, 123),
	}
	it.LastAccessed.Store(999)

	b, err := json.Marshal(it)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var out Item
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.LastAccessed.Load() != 999 {
		t.Fatalf("expected last_accessed=999, got %d", out.LastAccessed.Load())
	}
	if out.Value != "x" {
		t.Fatalf("expected value=x, got %#v", out.Value)
	}
	if !out.Exp.Equal(time.Unix(0, 123)) {
		t.Fatalf("expected exp preserved")
	}
}
